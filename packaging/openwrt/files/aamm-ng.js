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
    const nodeResults = modal.querySelector("[data-aamm-node-results]");

    function closeNodeResults() {
        if (!nodeResults || !findNodeButton) {
            return;
        }

        nodeResults.hidden = true;
        findNodeButton.setAttribute("aria-expanded", "false");
    }

    if (
        nodePicker &&
        findNodeButton &&
        nodeStatus &&
        targetInput &&
        nodeResults
    ) {
        findNodeButton.addEventListener("click", async function () {
            const endpoint = nodePicker.dataset.aammNodeEndpoint || "";

            nodeResults.replaceChildren();
            closeNodeResults();

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

                body.nodes.forEach(function (node) {
                    if (typeof node !== "string" || node.length === 0) {
                        return;
                    }

                    const resultButton = document.createElement("button");
                    resultButton.type = "button";
                    resultButton.className = "aamm-node-result";
                    resultButton.textContent = node;

                    resultButton.addEventListener("click", function () {
                        targetInput.value = node;
                        closeNodeResults();
                        nodeStatus.textContent =
                            "Node selected. You can edit the target before creating the alert.";
                        targetInput.focus();
                    });

                    nodeResults.appendChild(resultButton);
                });

                if (nodeResults.children.length === 0) {
                    nodeStatus.textContent =
                        "No nodes were found on the local AREDN mesh.";
                    targetInput.focus();
                }
                else {
                    nodeResults.hidden = false;
                    findNodeButton.setAttribute("aria-expanded", "true");
                    nodeStatus.textContent =
                        "Select a node from the local AREDN mesh, or enter a target manually.";

                    nodeResults.children[0].focus();
                }
            }
            catch (_) {
                nodeResults.replaceChildren();
                closeNodeResults();
                nodeStatus.textContent =
                    "Could not load local AREDN nodes. Enter a target manually.";
                targetInput.focus();
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
