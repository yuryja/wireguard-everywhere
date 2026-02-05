import json
import os

class I18n:
    def __init__(self, translations_path, default_lang='en'):
        self.translations = {}
        self.default_lang = default_lang
        self.load_translations(translations_path)

    def load_translations(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.translations = json.load(f)
        except Exception as e:
            print(f"Error loading translations: {e}")
            self.translations = {}

    def get_text(self, key, lang=None):
        if not lang:
            lang = self.default_lang
        
        # Fallback to default lang if lang not found
        if lang not in self.translations:
            lang = self.default_lang
            
        return self.translations.get(lang, {}).get(key, key)

    def get_available_languages(self):
        return {
            'en': 'English',
            'es': 'Español',
            'pt': 'Português',
            'fr': 'Français',
            'it': 'Italiano'
        }
