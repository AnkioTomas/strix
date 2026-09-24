# ocr_image

Local OCR over sandbox screenshots. Runs on the **host** (RapidOCR); reads
bytes via the live sandbox session. Bundled with Strix — no Docker image
change, no agent-side install.

Agent usage: `agent-browser screenshot` → `ocr_image(path=...)`.
Default path for image captchas / verification codes (no vision model).
