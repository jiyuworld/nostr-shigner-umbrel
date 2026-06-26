(function () {
    try {
        var t = localStorage.getItem("nostr-shigner-theme");
        if (!t)
            t = matchMedia("(prefers-color-scheme: light)").matches
                ? "light"
                : "dark";
        document.documentElement.dataset.theme = t;
    } catch (e) {}
})();
