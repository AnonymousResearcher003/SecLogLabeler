# SecLogLabeler

SecLogLabeler is a local web application for annotating a code log entry as security-related or non-security-related. For security-related logs, it also assigns six security sub-characteristic labels and displays the generated explanation.

## What it produces

- **Overall Security Flag**: `1` for security-related, `0` for non-security-related.
- **Security analyses**: Confidentiality (`C`), Integrity (`I`), Non-repudiation (`N`), Accountability (`Ac`), Authenticity (`Au`), and Resistance (`R`).
- **Expandable reasoning** for labels classified as `1`.
- **JSON and CSV exports** of the latest result.

## Prerequisites

- Python 3.10 or newer.
- For local LLM inference: the downloaded GGUF model at `models/Qwen2.5-7B-Instruct-Q4_K_M.gguf` and the `llama-cpp-python` package.

The application can still run if the LLM package or model is unavailable, but it will use a limited keyword-based fallback instead of model inference.

## Setup 

1. Install Git and Python 3.10 or newer if needed, then confirm both are available:

   ```bash
   git --version
   python3 --version
   ```

2. On the GitHub repository page, select **Code**, copy the HTTPS clone URL, and clone it. Replace the placeholder below with the URL you copied:

   ```bash
   git clone URL_PLACEHOLDER
   ```

3. Enter the newly cloned project directory. Replace `REPOSITORY` with the folder created by `git clone`:

   ```bash
   cd SecLogLabeler
   ```

4. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install the local LLM runtime:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

6. Download the required Qwen2.5 Q4_K_M GGUF model (approximately 4.7 GB) into the expected `models/` location:

   ```bash
   mkdir -p models
   curl -L --fail --output models/Qwen2.5-7B-Instruct-Q4_K_M.gguf \
     "https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-Q4_K_M.gguf?download=true"
   ```

   The model file is hosted by [bartowski/Qwen2.5-7B-Instruct-GGUF on Hugging Face](https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF). Leave the filename unchanged: the application is configured to look for this exact name.

7. Confirm that the download completed:

   ```bash
   ls models/Qwen2.5-7B-Instruct-Q4_K_M.gguf
   ```

### If you already have the project folder

Open Terminal and change into it, then continue from step 4 above:

```bash
cd "/path/to/SecLogLabeler"
```

## Run the web application

1. From the project folder, start the server:

   ```bash
   python3 app.py
   ```

2. Wait for this message:

   ```text
   SecLogLabeler running at http://127.0.0.1:5000
   ```

3. Open the following address in a browser on the same computer:

   ```text
   http://127.0.0.1:5000
   ```

4. Keep the terminal running while using the application. To stop the server, press `Ctrl+C` in that terminal.

## How to use the interface

1. Paste a log entry into **Paste log text**, or click one of the two example links:
   - **Try OpenSSH Failure Example**
   - **Try Apache Access Leak Example**

2. Click **Annotate**.

3. Review **Generated Labels**:
   - Every analysis has a **Model Classification** value of `0` or `1`.
   - A value of `1` can be opened to view its reasoning.
   - A value of `0` intentionally has no reasoning panel.

4. Review the **Security Attributes** panel on the right. Attributes classified as `1` are highlighted.

5. Use **Export JSON** or **Export CSV** after a successful result to save the input log, overall flag, all six labels, generated reasoning, model mode, and export time.

## LLM mode and fallback mode

The status line shows how the result was produced:

- `mode: llm` — the local Qwen GGUF model was successfully loaded and used.
- `mode: fallback` — the model runtime or model could not be used, so simple keyword rules were used instead.

Fallback output is useful for demonstrating the interface, but it is not equivalent to LLM-generated classification. For LLM mode, install the requirements and ensure the GGUF file is present in `models/` before restarting the app.

## Troubleshooting

### The browser says annotation failed

- Check that `python3 app.py` is still running in Terminal.
- Confirm that you opened `http://127.0.0.1:5000`, not a different address.
- Read the status message in the page; it includes the available server/HTTP error.
- Restart the server after changing Python code.

### The page does not reflect a frontend change

Hard-refresh the browser. On macOS, use `Command+Shift+R`.

### The app reports fallback mode

Install dependencies and verify the model path:

```bash
python3 -m pip install -r requirements.txt
ls models/Qwen2.5-7B-Instruct-Q4_K_M.gguf
```

Then restart the server.

## Project structure

```text
app.py                         HTTP server and /annotate API endpoint
sec_log_labeler_framework.py   Binary and six-label classification pipeline
templates/index.html           Browser UI, accordions, examples, and exports
models/                        Local GGUF model file
requirements.txt               Optional local LLM runtime dependency
```

