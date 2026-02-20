import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { LANGUAGE_STORAGE_KEY, LanguageCode, SUPPORTED_LANGUAGES, TRANSLATIONS, TranslationKey } from './translations';

interface LanguageContextValue {
  language: LanguageCode;
  setLanguage: (nextLanguage: LanguageCode) => void;
  t: (key: TranslationKey) => string;
}

const LanguageContext = createContext<LanguageContextValue | undefined>(undefined);

/** Normalize arbitrary language strings into supported app language codes. */
const normalizeLanguage = (value: string | null | undefined): LanguageCode | null => {
  if (!value) return null;

  const normalized = value.toLowerCase().trim();
  if (!normalized) return null;

  if (normalized.startsWith('de')) return 'de';
  if (normalized.startsWith('en')) return 'en';

  return null;
};

/** Resolve initial language from app storage, Home Assistant storage, or browser locale. */
const detectLanguage = (): LanguageCode => {
  if (typeof window === 'undefined') {
    return 'en';
  }

  const storedLanguage = normalizeLanguage(window.localStorage.getItem(LANGUAGE_STORAGE_KEY));
  if (storedLanguage) {
    return storedLanguage;
  }

  const directHaLanguage = normalizeLanguage(window.localStorage.getItem('selectedLanguage'))
    ?? normalizeLanguage(window.localStorage.getItem('hassSelectedLanguage'))
    ?? normalizeLanguage(window.localStorage.getItem('hass-language'));

  if (directHaLanguage) {
    return directHaLanguage;
  }

  try {
    const hassFrontendRaw = window.localStorage.getItem('hassFrontend');
    if (hassFrontendRaw) {
      const hassFrontend = JSON.parse(hassFrontendRaw) as { selectedLanguage?: string };
      const hassLanguage = normalizeLanguage(hassFrontend.selectedLanguage);
      if (hassLanguage) {
        return hassLanguage;
      }
    }
  } catch {
    // Ignore malformed localStorage data and continue fallback chain.
  }

  const browserLanguage = normalizeLanguage(window.navigator.language);
  if (browserLanguage) {
    return browserLanguage;
  }

  return 'en';
};

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [language, setLanguageState] = useState<LanguageCode>(() => detectLanguage());

  const setLanguage = useCallback((nextLanguage: LanguageCode) => {
    setLanguageState(nextLanguage);

    if (typeof window !== 'undefined') {
      window.localStorage.setItem(LANGUAGE_STORAGE_KEY, nextLanguage);
    }
  }, []);

  const t = useCallback((key: TranslationKey): string => {
    return TRANSLATIONS[language][key] ?? TRANSLATIONS.en[key] ?? key;
  }, [language]);

  const contextValue = useMemo(() => ({
    language,
    setLanguage,
    t
  }), [language, setLanguage, t]);

  return (
    <LanguageContext.Provider value={contextValue}>
      {children}
    </LanguageContext.Provider>
  );
};

/** Typed hook wrapper around the language context with provider guard. */
export const useLanguage = (): LanguageContextValue => {
  const context = useContext(LanguageContext);

  if (!context) {
    throw new Error('useLanguage must be used within LanguageProvider.');
  }

  return context;
};

export { SUPPORTED_LANGUAGES };
