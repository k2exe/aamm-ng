(function () {
    "use strict";

    const modal = document.getElementById("ctrl-modal");

    if (!modal) {
        return;
    }

    const returnURL = modal.dataset.returnUrl || "./";

    function returnToDashboard() {
        window.location.assign(returnURL);
    }

    modal.querySelectorAll("[data-aamm-close]").forEach(function (button) {
        button.addEventListener("click", returnToDashboard);
    });

    modal.addEventListener("cancel", function (event) {
        event.preventDefault();
        returnToDashboard();
    });

    if (typeof modal.showModal === "function") {
        modal.showModal();
    }
    else {
        modal.setAttribute("open", "");
    }
})();
