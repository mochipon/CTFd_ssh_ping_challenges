CTFd._internal.challenge.data = undefined;
CTFd._internal.challenge.renderer = null;
CTFd._internal.challenge.preRender = function () {};
CTFd._internal.challenge.render = null;
CTFd._internal.challenge.postRender = function () {};

CTFd._internal.challenge.submit = function (preview) {
  const challenge_id = parseInt(CTFd.lib.$("#challenge-id").val(), 10);
  const submission = CTFd.lib.$("#challenge-input").val();
  const body = {
    challenge_id,
    submission,
  };
  const params = {};
  if (preview) {
    params.preview = true;
  }
  return CTFd.api.post_challenge_attempt(params, body).then(response => {
    if (response.status === 429 || response.status === 403) {
      return response;
    }
    return response;
  });
};

CTFd.plugin.run(_CTFd => {
  const $ = _CTFd.lib.$;
  const format = (text, ...args) => args.reduce(
    (result, arg, idx) => result.replace(new RegExp(`\\{${idx}\\}`, 'g'), arg),
    text,
  );

  const translations = {
    en: {
      banner: "This challenge will attempt to reach {0}.",
      bannerMissing: "No pod has been assigned to your team yet.",
      input: "Attempting ping to {0}",
      inputWithSource: "Attempting ping to {0} from {1}",
      inputMissing: "Attempting ping to unassigned host",
      button: "Run Ping",
    },
    ja: {
      banner: "この課題は {0} への ping を試みます。",
      bannerMissing: "あなたのチームには Pod がまだ割り当てられていません。",
      input: "{0} への ping を試みます",
      inputWithSource: "{1} から {0} への ping を試行します",
      inputMissing: "送信先が割り当てられていません",
      button: "Ping を実行",
    },
  };

  const supported = new Set(Object.keys(translations));
  const normalizeLang = lang => {
    if (!lang) return 'en';
    const short = lang.toLowerCase().split('-')[0];
    return supported.has(short) ? short : 'en';
  };

  const detectLanguage = () => {
    if (typeof ctxLocale !== 'undefined') {
      return normalizeLang(ctxLocale);
    }
    if (navigator.language) {
      return normalizeLang(navigator.language);
    }
    return 'en';
  };

  let selectedLang = null;
  const translate = key => {
    const lang = selectedLang || detectLanguage();
    const table = translations[lang] || translations.en;
    return table[key] ?? translations.en[key] ?? key;
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
      if (bastion) {
        input.value = format(translate('inputWithSource'), resolved, bastion);
      } else {
        input.value = format(translate('input'), resolved);
      }
    } else {
      banner.textContent = translate('bannerMissing');
      input.value = translate('inputMissing');
    }

    button.textContent = translate('button');
  };

  window.LabPods = Object.assign(window.LabPods || {}, {
    setLanguage: lang => {
      selectedLang = normalizeLang(lang);
      applyTranslations();
    },
    getLanguage: () => selectedLang || detectLanguage(),
    translate: key => translate(key),
    applyTranslations,
  });

  $(function () {
    applyTranslations();
  });
});
