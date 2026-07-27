#!/usr/bin/env python3
"""Minimal ComfyUI API client: submit a basic SDXL txt2img workflow, wait for
completion, save the resulting image(s) to a given output path."""
import json
import sys
import time
import urllib.request
import uuid

COMFY_URL = "http://127.0.0.1:8188"


def build_workflow(ckpt, positive, negative, width, height, seed, steps=30, cfg=6.0):
    return {
        "3": {
            "class_type": "KSampler",
            "inputs": {
                "seed": seed, "steps": steps, "cfg": cfg,
                "sampler_name": "dpmpp_2m", "scheduler": "karras", "denoise": 1.0,
                "model": ["4", 0], "positive": ["6", 0], "negative": ["7", 0],
                "latent_image": ["5", 0],
            },
        },
        "4": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": ckpt}},
        "5": {"class_type": "EmptyLatentImage", "inputs": {"width": width, "height": height, "batch_size": 1}},
        "6": {"class_type": "CLIPTextEncode", "inputs": {"text": positive, "clip": ["4", 1]}},
        "7": {"class_type": "CLIPTextEncode", "inputs": {"text": negative, "clip": ["4", 1]}},
        "8": {"class_type": "VAEDecode", "inputs": {"samples": ["3", 0], "vae": ["4", 2]}},
        "9": {"class_type": "SaveImage", "inputs": {"images": ["8", 0], "filename_prefix": "gen"}},
    }


def submit(workflow):
    client_id = str(uuid.uuid4())
    body = json.dumps({"prompt": workflow, "client_id": client_id}).encode()
    req = urllib.request.Request(f"{COMFY_URL}/prompt", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["prompt_id"]


def wait_for_result(prompt_id, timeout=180):
    start = time.time()
    while time.time() - start < timeout:
        with urllib.request.urlopen(f"{COMFY_URL}/history/{prompt_id}", timeout=10) as resp:
            hist = json.loads(resp.read())
        if prompt_id in hist:
            return hist[prompt_id]
        time.sleep(2)
    raise TimeoutError(f"prompt {prompt_id} did not finish in {timeout}s")


def fetch_image(filename, subfolder, folder_type, out_path):
    from urllib.parse import urlencode
    qs = urlencode({"filename": filename, "subfolder": subfolder, "type": folder_type})
    with urllib.request.urlopen(f"{COMFY_URL}/view?{qs}", timeout=30) as resp:
        data = resp.read()
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def generate(ckpt, positive, negative, width, height, seed, out_path):
    wf = build_workflow(ckpt, positive, negative, width, height, seed)
    prompt_id = submit(wf)
    print(f"submitted prompt_id={prompt_id}, waiting...")
    result = wait_for_result(prompt_id)
    outputs = result.get("outputs", {})
    images = outputs.get("9", {}).get("images", [])
    if not images:
        raise RuntimeError(f"no images in output: {json.dumps(result)[:500]}")
    img = images[0]
    fetch_image(img["filename"], img.get("subfolder", ""), img.get("type", "output"), out_path)
    print(f"saved -> {out_path}")


if __name__ == "__main__":
    ckpt, positive, negative, width, height, seed, out_path = sys.argv[1:8]
    generate(ckpt, positive, negative, int(width), int(height), int(seed), out_path)
