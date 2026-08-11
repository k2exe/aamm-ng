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

    const nodePicker = modal.querySelector("[data-aamm-node-endpoint]");
    const findNodeButton = modal.querySelector("[data-aamm-find-node]");
    const nodeStatus = modal.querySelector("[data-aamm-node-status]");
    const targetInput = modal.querySelector("#target");
    const nodeList = modal.querySelector("#aamm-local-nodes");

    if (
        nodePicker &&
        findNodeButton &&
        nodeStatus &&
        targetInput &&
        nodeList
    ) {
        findNodeButton.addEventListener("click", async function () {
            const endpoint = nodePicker.dataset.aammNodeEndpoint || "";

            if (!endpoint) {
                nodeStatus.textContent =
                    "Local node discovery is unavailable. Enter a target manually.";
                return;
            }

            findNodeButton.disabled = true;
            nodeStatus.textContent = "Finding local AREDN nodes...";

            try {
                const response = await fetch(endpoint, {
                    method: "GET",
                    credentials: "same-origin",
                    headers: {
                        "Accept": "application/json"
                    }
                });

                if (!response.ok) {
                    throw new Error("node discovery request failed");
                }

                const body = await response.json();

                if (!body || !Array.isArray(body.nodes)) {
                    throw new Error("invalid node discovery response");
                }

                nodeList.replaceChildren();

                body.nodes.forEach(function (node) {
                    if (typeof node !== "string") {
                        return;
                    }

                    const option = document.createElement("option");
                    option.value = node;
                    nodeList.appendChild(option);
                });

                if (nodeList.children.length === 0) {
                    nodeStatus.textContent =
                        "No directly known local AREDN nodes were found.";
                }
                else {
                    nodeStatus.textContent =
                        "Local node suggestions are ready. Type or select a target.";
                }

                targetInput.focus();
            }
            catch (_) {
                nodeStatus.textContent =
                    "Could not load local AREDN nodes. Enter a target manually.";
            }
            finally {
                findNodeButton.disabled = false;
            }
        });
    }

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
