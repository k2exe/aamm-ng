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

    const confirmation = modal.querySelector("[data-aamm-confirm-target]");
    const deleteButton = modal.querySelector("[data-aamm-delete-submit]");

    if (confirmation && deleteButton) {
        const requiredTarget = confirmation.dataset.aammConfirmTarget || "";

        function updateDeleteButton() {
            deleteButton.disabled = confirmation.value !== requiredTarget;
        }

        confirmation.addEventListener("input", updateDeleteButton);
        updateDeleteButton();
    }

    if (typeof modal.showModal === "function") {
        modal.showModal();
    }
    else {
        modal.setAttribute("open", "");
    }
})();
