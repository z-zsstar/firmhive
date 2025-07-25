import os
import time
import openai
import json
from openai import OpenAI
from typing import List, Dict, Any, Optional

class LLMClient:
    _instance = None
    
    def __new__(cls, config_path: str = 'config.ini'):
        if cls._instance is None:
            cls._instance = super(LLMClient, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, config_path: str = 'config.ini'):
        if not hasattr(self, 'initialized'):
            import configparser
            self.config = configparser.ConfigParser()
            self.config.read(config_path, encoding='utf-8')
            
            self.active_model = self.config.get('common', 'active_model', fallback='openai')
            
            self.api_key = self.config.get(self.active_model, 'api_key', fallback=os.environ.get('OPENAI_API_KEY'))
            self.model = self.config.get(self.active_model, 'model', fallback='gpt-4o')
            self.base_url = self.config.get(self.active_model, 'base_url', fallback=None)
            self.org_id = self.config.get(self.active_model, 'org_id', fallback=None)
            self.temperature = float(self.config.get(self.active_model, 'temperature', fallback='0'))
            
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url if self.base_url else None,
                organization=self.org_id if self.org_id else None
            )
            
            self.callbacks = []
            self.initialized = True
    
    def add_callback(self, callback):
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def remove_callback(self, callback):
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def __call__(self, messages: List[Dict[str, str]], stream: bool = False, 
                timeout: Optional[float] = None, max_retries: int = 3, output_dir: Optional[str] = None) -> Dict[str, Any]:
        for callback in self.callbacks:
            if hasattr(callback, 'on_llm_start'):
                callback.on_llm_start({"name": self.active_model}, [msg.get('content', '') for msg in messages])
        
        retry_count = 0
        while retry_count < max_retries:
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                    stream=stream,
                    timeout=timeout,
                    seed=42
                )
                
                if stream:
                    collected_chunks = []
                    collected_content = ""
                    
                    for chunk in response:
                        collected_chunks.append(chunk)
                        if chunk.choices and chunk.choices[0].delta.content:
                            content_chunk = chunk.choices[0].delta.content
                            collected_content += content_chunk
                            
                            for callback in self.callbacks:
                                if hasattr(callback, 'on_llm_new_token'):
                                    callback.on_llm_new_token(content_chunk)
                    
                    result = {
                        "content": collected_content,
                        "usage": {
                            "prompt_tokens": 0,
                            "completion_tokens": 0,
                            "total_tokens": 0
                        },
                        "prompt_messages": messages
                    }
                else:
                    result = {
                        "content": response.choices[0].message.content,
                        "usage": {
                            "prompt_tokens": response.usage.prompt_tokens,
                            "completion_tokens": response.usage.completion_tokens,
                            "total_tokens": response.usage.total_tokens
                        },
                        "prompt_messages": messages
                    }
                
                if output_dir and not stream:
                    try:
                        os.makedirs(output_dir, exist_ok=True)
                        log_file_path = os.path.join(output_dir, 'token_usage.jsonl')
                        log_entry = result['usage']
                        with open(log_file_path, 'a', encoding='utf-8') as f:
                            f.write(json.dumps(log_entry, ensure_ascii=False, default=str) + '\n')
                    except Exception as e:
                        print(f"[LLMClient] Warning: Failed to log token usage to {output_dir}. Error: {e}")
                
                for callback in self.callbacks:
                    if hasattr(callback, 'on_llm_end'):
                        callback.on_llm_end({
                            "llm_output": {
                                "token_usage": result["usage"],
                                "model_name": self.model
                            },
                            "generations": [[{"text": result["content"]}]]
                        })
                
                return result
                
            except (openai.APIError, openai.APIConnectionError, openai.RateLimitError) as e:
                retry_count += 1
                wait_time = 2 ** retry_count
                time.sleep(wait_time)
                
            except Exception as e:
                raise
        
        raise Exception(f"Failed after {max_retries} retries")

class DefaultCallback:
    """Default callback implementation for LLMClient that tracks LLM interactions without logging"""
    
    def __init__(self):
        self.start_time = None
        self.total_tokens = 0
        
    def on_llm_start(self, serialized, messages):
        self.start_time = time.time()
        
    def on_llm_new_token(self, token):
        pass
        
    def on_llm_end(self, response):
        if self.start_time:
            token_usage = response.get("llm_output", {}).get("token_usage", {})
            total_tokens = token_usage.get("total_tokens", 0)
            self.total_tokens += total_tokens
        
    def on_llm_error(self, error):
        pass
        
    def reset_stats(self):
        self.total_tokens = 0

if __name__ == "__main__":
    llm_client = LLMClient()
    
    test_message = [{"role": "user", "content": "Hello, please briefly introduce yourself."}]
    
    response = llm_client(test_message)
    print(f"\nLLM response:\n{response['content']}\n")
    print(f"\nPrompt messages:\n{response['prompt_messages']}\n")
    print(f"Token usage:\n{response['usage']}\n")
