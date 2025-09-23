CTFd._internal.challenge.data = undefined;

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function() {};

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function() {};

CTFd._internal.challenge.submit = function(preview) {
  var challenge_id = parseInt(CTFd.lib.$("#challenge-id").val());
  var submission = CTFd.lib.$("#challenge-input").val();

  var body = {
    challenge_id: challenge_id,
    submission: submission
  };
  var params = {};
  if (preview) {
    params["preview"] = true;
  }

  return CTFd.api.post_challenge_attempt(params, body).then(function(response) {
    if (response.status === 429) {
      // User was ratelimited but process response
      return response;
    }
    if (response.status === 403) {
      // User is not logged in or CTF is paused.
      return response;
    }
    return response;
  });
};

CTFd.plugin.run(_CTFd => {
  const $ = _CTFd.lib.$;

  const format = (str, ...args) => {
    for (const [i, arg] of args.entries()) {
      const regExp = new RegExp(`\\{${i}\\}`, 'g')
      str = str.replace(regExp, arg)
    }
    return str
  }

  // --- Async: only used during initialization or explicit fetch, not during rendering ---
  const fetchCTFdUserLanguage = async () => {
    try {
      const res = await CTFd.fetch('/api/v1/users/me', {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      if (!res.ok) {
        console.error('fetchCTFdUserLanguage: HTTP error', res.status);
        return null;
      }
      const json = await res.json();
      if (!json?.success) return null;

      let lang = json?.data?.language ?? null;
      if (typeof lang === 'string' && lang.length > 0) {
        // "en-US", "pt_BR" -> "en", "pt"
        lang = lang.toLowerCase().split(/[-_]/)[0];
      } else {
        lang = null;
      }
      return lang;
    } catch (err) {
      console.error('fetchCTFdUserLanguage error:', err);
      return null;
    }
  };

  // --- i18n dictionary ------------------------------------------------------
  const translations = {
    en: {
      banner: "This challenge will attempt to ping {0}.",
      bannerMissing: "No pod has been assigned to your team yet.",
      inputWithSource: "Attempting ping to {0} from {1}",
      inputMissing: "Attempting ping to unassigned host",
      button: "Run",
    },
    ja: {
      banner: "この課題を達成するには {0} に ping できる必要があります。",
      bannerMissing: "あなたのチームには Pod がまだ割り当てられていません。",
      inputWithSource: "{1} から {0} への ping",
      inputMissing: "送信先が割り当てられていません",
      button: "実行",
    },
  };

  // --- language helpers -----------------------------------------------------
  const supported = new Set(Object.keys(translations));
  let selectedLang = null; // user override if set via setLanguage()
  let langResolved = false;
  const normalizeLang = (lang) => {
    if (!lang) return 'en';
    const short = lang.toLowerCase().split('-')[0]; // e.g., "ja-JP" -> "ja"
    return supported.has(short) ? short : 'en';
  };


  const detectLanguage = async () => {
    const userLocale = await fetchCTFdUserLanguage();
    if (userLocale !== null) {
      return normalizeLang(userLocale);
    }
    if (typeof navigator !== 'undefined' && navigator.language) {
      return normalizeLang(navigator.language);
    }
    return 'en';
  };

  const resolveLanguageOnce = async () => {
    if (langResolved) return selectedLang;
    try {
      const detected = await detectLanguage();
      selectedLang = detected || 'en';
    } catch (e) {
      console.warn('Language detection failed, falling back to en:', e);
      selectedLang = 'en';
    } finally {
      langResolved = true;
    }
    return selectedLang;
  };

  // --- Synchronous translation helpers used by rendering ---
  const translate = (key) => {
    const table = translations[selectedLang] || translations.en;
    return (table && key in table) ? table[key] : (translations.en[key] ?? key);
  };

  const applyTranslations = () => {
    const banner = document.getElementById("ssh-ping-target");
    const input = document.getElementById("challenge-input");
    const button = document.getElementById("challenge-submit");
    if (!banner || !input || !button) return;

    const hasTarget = banner.getAttribute("data-has-target") === "true";
    const resolved = banner.getAttribute("data-resolved") || "";
    const bastion = banner.getAttribute("data-bastion") || "";

    if (hasTarget && resolved) {
      banner.textContent = format(translate('banner'), resolved);
      input.value = format(translate('inputWithSource'), resolved, bastion);
    } else {
      banner.textContent = translate('bannerMissing');
      input.value = translate('inputMissing');
    }

    button.textContent = translate('button');
  };

  // Expose a synchronous API to the page
  window.LabPods = Object.assign(window.LabPods || {}, {
    setLanguage: (lang) => {
      selectedLang = normalizeLang(lang);
      langResolved = true;
      applyTranslations();
    },
    getLanguage: () => selectedLang,
    translate: (key) => translate(key),
    applyTranslations,
  });

  // Initialize: resolve language (async) first, then render (sync)
  $(function () {
    (async () => {
      await resolveLanguageOnce();
      applyTranslations();
    })();
  });
});
