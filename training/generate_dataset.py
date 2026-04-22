#!/usr/bin/env python3
"""
Crypto CTF Dataset Generator
Parses raw CTF writeups and generates training-ready JSONL dataset
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

def extract_challenge_info(readme_path: str) -> Optional[Dict]:
    """Parse a challenge README to extract metadata."""
    try:
        with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Extract year from path
        path_parts = Path(readme_path).parts
        year = None
        for part in path_parts:
            if part.isdigit() and len(part) == 4:
                year = int(part)
                break
        
        # Extract CTF name
        ctf_name = None
        for part in path_parts:
            if 'ctf' in part.lower() or 'ctf' in part.lower():
                ctf_name = part
                break
        
        # Extract challenge name from directory
        challenge_name = path_parts[-2] if len(path_parts) >= 2 else "unknown"
        
        # Detect category
        category = detect_category(readme_path, content)
        
        # Detect difficulty
        difficulty = detect_difficulty(content, challenge_name)
        
        return {
            "id": f"ctf-{year or 'unknown'}-{challenge_name.lower().replace(' ', '-')}",
            "title": challenge_name.replace('-', ' ').replace('_', ' ').title(),
            "category": category,
            "difficulty": difficulty,
            "ctf_event": ctf_name or "unknown",
            "year": year,
            "description": extract_description(content),
            "path": str(readme_path)
        }
    except Exception as e:
        return None

def detect_category(path: str, content: str) -> str:
    """Detect challenge category from path and content."""
    path_lower = path.lower()
    content_lower = content.lower()
    
    if 'rsa' in path_lower or 'rsa' in content_lower:
        return "rsa"
    elif 'ecc' in path_lower or 'elliptic' in content_lower:
        return "ecc"
    elif 'aes' in path_lower or 'block' in path_lower:
        return "blockcipher"
    elif 'stream' in path_lower or 'chacha' in path_lower or 'lsfr' in path_lower:
        return "streamcipher"
    elif 'hash' in path_lower or 'md5' in path_lower or 'sha' in path_lower:
        return "hash"
    elif 'lattice' in path_lower or 'lll' in path_lower or 'coppersmith' in path_lower:
        return "lattice"
    elif 'ecdsa' in path_lower:
        return "ecdsa"
    elif 'prng' in path_lower or 'mt19937' in path_lower or 'random' in path_lower:
        return "prng"
    elif 'classic' in path_lower or 'caesar' in path_lower or 'vigenere' in path_lower or 'rot13' in path_lower:
        return "classic"
    elif 'base64' in path_lower or 'encoding' in path_lower:
        return "encoding"
    else:
        return "misc"

def detect_difficulty(content: str, name: str) -> int:
    """Detect difficulty level 1-5."""
    content_lower = content.lower()
    name_lower = name.lower()
    
    # Easy indicators
    if any(x in content_lower for x in ['easy', 'baby', 'simple', 'basic', 'intro']):
        return 1
    # Medium indicators
    if any(x in content_lower for x in ['medium', 'moderate', 'normal']):
        return 2
    # Hard indicators
    if any(x in content_lower for x in ['hard', 'advanced', 'bleichenbacher', 'coppersmith', 'lattice']):
        return 4
    # Expert indicators
    if any(x in content_lower for x in ['expert', 'insane', 'challenging', 'oll', 'babystep']):
        return 5
    
    # Name-based heuristics
    if 'baby' in name_lower or 'easy' in name_lower:
        return 1
    if 'hard' in name_lower or 'expert' in name_lower:
        return 4
    
    return 3  # Default medium

def extract_description(content: str) -> str:
    """Extract challenge description from README."""
    lines = content.split('\n')
    desc_lines = []
    in_desc = False
    
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('```'):
            if len(line) > 20:
                desc_lines.append(line)
        if len(desc_lines) >= 5:
            break
    
    return ' '.join(desc_lines[:3])[:200]

def extract_code_files(challenge_dir: Path) -> List[Dict]:
    """Extract code files from challenge directory."""
    code_files = []
    
    for ext in ['.py', '.sage', '.sh', '.txt']:
        for f in challenge_dir.glob(f'*{ext}'):
            if f.name not in ['README.md', 'readme.md']:
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                        code_files.append({
                            "filename": f.name,
                            "language": "python" if ext == '.py' else "bash" if ext == '.sh' else "text",
                            "content": file.read()[:2000]  # Limit size
                        })
                except:
                    pass
    
    return code_files

def process_writeups(raw_dir: str, output_file: str):
    """Process all writeups and generate training dataset."""
    raw_path = Path(raw_dir)
    all_challenges = []
    
    # Walk through all cloned repos
    for repo_dir in raw_path.iterdir():
        if repo_dir.is_dir():
            for readme_path in repo_dir.rglob('README.md'):
                challenge_info = extract_challenge_info(str(readme_path))
                if challenge_info:
                    challenge_dir = readme_path.parent
                    challenge_info["code_files"] = extract_code_files(challenge_dir)
                    all_challenges.append(challenge_info)
    
    # Write JSONL
    with open(output_file, 'w') as f:
        for challenge in all_challenges:
            f.write(json.dumps(challenge) + '\n')
    
    print(f"Processed {len(all_challenges)} challenges")
    
    # Write category stats
    categories = {}
    for c in all_challenges:
        cat = c['category']
        categories[cat] = categories.get(cat, 0) + 1
    
    print("\nCategory breakdown:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

def generate_training_prompts(input_jsonl: str, output_file: str):
    """Generate prompt-completion pairs for fine-tuning."""
    with open(input_jsonl, 'r') as f:
        challenges = [json.loads(line) for line in f]
    
    with open(output_file, 'w') as f:
        for c in challenges:
            # Create training prompt
            prompt = f"""Solve this CTF crypto challenge:

Title: {c['title']}
Category: {c['category']}
Difficulty: {c['difficulty']}/5
CTF Event: {c['ctf_event']} {c['year']}
Description: {c['description']}

What is the attack strategy and how would you solve this?"""
            
            # Create completion with solution approach
            completion = f"""To solve this {c['category']} challenge:

## Analysis
This is a {c['category']} challenge rated difficulty {c['difficulty']}/5.

## Solution Strategy
"""
            
            # Add code if available
            if c.get('code_files'):
                completion += "## Exploit Code\n\n```python\n"
                for cf in c['code_files'][:2]:  # Limit to 2 files
                    completion += f"# File: {cf['filename']}\n{cf['content']}\n\n"
                completion += "```\n"
            
            completion += f"\n## Flag Format\nThe flag typically follows the format: flag{{...}}"
            
            # Write as JSONL for fine-tuning
            f.write(json.dumps({
                "prompt": prompt,
                "completion": completion
            }) + '\n')

if __name__ == "__main__":
    import sys
    
    raw_dir = "/home/workspace/crypto-ctf-solver/data/raw"
    processed_dir = "/home/workspace/crypto-ctf-solver/data/processed"
    
    os.makedirs(processed_dir, exist_ok=True)
    
    print("Processing CTF writeups...")
    process_writeups(raw_dir, f"{processed_dir}/challenges.jsonl")
    
    print("\nGenerating training prompts...")
    generate_training_prompts(
        f"{processed_dir}/challenges.jsonl",
        f"{processed_dir}/training_prompts.jsonl"
    )
    
    print("\nDone!")
