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
      const regExp = new RegExp(`\\{${i}\\}`, 'g');
      str = str.replace(regExp, arg);
    }
    return str;
  };

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
      resolved: "This challenge will attempt to ping <code>{0}</code> from <code>{1}</code>.",
      unassigned: "No pod has been assigned to your team yet. Please contact the administrators.",
      inputUnassigned: "Unable to attempt ping as target is unknown. Please contact the administrators.",
      button: "Run",
    },
    ja: {
      resolved: "この課題は <code>{1}</code> から <code>{0}</code> へ ping を実行します。",
      unassigned: "あなたのチームには Pod がまだ割り当てられていません。管理者に連絡してください。",
      inputUnassigned: "宛先が不明なので実行することができません。管理者に連絡してください。",
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
    const infoEl = document.getElementById("ssh-ping-target-info");
    if (infoEl) {
      const resolved = infoEl.getAttribute("data-resolved") || "";
      const bastion = infoEl.getAttribute("data-bastion") || "";

      if (resolved && bastion) {
        infoEl.innerHTML = format(translate("resolved"), resolved, bastion);
      } else {
        infoEl.innerHTML = translate("unassigned");
      }
    }

    const inputEl = document.getElementById("challenge-input");
    if (inputEl) {
      const resolved = inputEl.getAttribute("data-resolved") || "";
      const bastion = inputEl.getAttribute("data-bastion") || "";

      if (resolved && bastion) {
        // keeping the input value as is
      } else {
        inputEl.value = translate("inputUnassigned");
      }
    }

    const buttonEl = document.getElementById("challenge-submit");
    if (buttonEl) {
      buttonEl.textContent = translate("button");
    }
  };

  // Expose a synchronous API to the page
  window.SshPingChallenges = Object.assign(window.SshPingChallenges || {}, {
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
