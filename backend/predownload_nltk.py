"""
Run this once during the build process (not at app runtime) to download
NLTK's data into the project's nltk_data/ folder, so it can be bundled
alongside the packaged executable and the app works fully offline on
whatever machine it's eventually run on.
"""
import nltk
from paths import NLTK_DATA_DIR

print(f"Downloading NLTK data into {NLTK_DATA_DIR} ...")
nltk.download("punkt", download_dir=NLTK_DATA_DIR)
nltk.download("stopwords", download_dir=NLTK_DATA_DIR)
nltk.download("wordnet", download_dir=NLTK_DATA_DIR)
print("Done.")
