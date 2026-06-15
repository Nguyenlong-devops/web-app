/* ==================================================
   PV AUTOMATION PORTAL V2
================================================== */

let currentDeleteId = null;

/* ==================================================
   THEME
================================================== */

function toggleTheme() {

    const html = document.documentElement;

    const current =
        html.getAttribute("data-theme");

    if (current === "light") {

        html.setAttribute("data-theme", "dark");

        localStorage.setItem(
            "pv_theme",
            "dark"
        );

        document.querySelector(
            ".theme-toggle"
        ).innerHTML = "?? Night Mode";

    } else {

        html.setAttribute(
            "data-theme",
            "light"
        );

        localStorage.setItem(
            "pv_theme",
            "light"
        );

        document.querySelector(
            ".theme-toggle"
        ).innerHTML = "?? Light Mode";
    }
}

/* ==================================================
   TOAST
================================================== */

function showToast(
    message,
    type = "info"
) {

    const container =
        document.getElementById(
            "toastContainer"
        );

    if (!container) return;

    const toast =
        document.createElement("div");

    toast.className =
        `toast toast-${type}`;

    toast.innerHTML = message;

    container.appendChild(
        toast
    );

    setTimeout(() => {

        toast.style.opacity = "0";

        setTimeout(() => {

            toast.remove();

        }, 300);

    }, 3500);
}

/* ==================================================
   LOADING
================================================== */

function showLoading() {

    const overlay =
        document.getElementById(
            "loadingOverlay"
        );

    if (overlay)
        overlay.classList.add(
            "show"
        );
}

function hideLoading() {

    const overlay =
        document.getElementById(
            "loadingOverlay"
        );

    if (overlay)
        overlay.classList.remove(
            "show"
        );
}

/* ==================================================
   COLLAPSIBLE PANELS
================================================== */

function togglePanel(id) {

    const panel =
        document.getElementById(id);

    if (!panel) return;

    const hidden =
        panel.classList.contains(
            "hidden"
        );

    document
        .querySelectorAll(
            "#create-user-panel,#license-panel,#assign-license-panel"
        )
        .forEach(el => {

            el.classList.add(
                "hidden"
            );

        });

    if (hidden) {

        panel.classList.remove(
            "hidden"
        );

        setTimeout(() => {

            panel.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        }, 100);
    }
}

/* ==================================================
   USER SEARCH
================================================== */

function filterUserTable() {

    const input =
        document.getElementById(
            "userSearchInput"
        );

    const filter =
        input.value.toUpperCase();

    const table =
        document.getElementById(
            "userTable"
        );

    if (!table) return;

    const rows =
        table.getElementsByTagName(
            "tr"
        );

    for (
        let i = 1;
        i < rows.length;
        i++
    ) {

        const userCol =
            rows[i]
            .getElementsByTagName(
                "td"
            )[0];

        const nameCol =
            rows[i]
            .getElementsByTagName(
                "td"
            )[1];

        if (!userCol || !nameCol)
            continue;

        const userText =
            userCol.textContent ||
            userCol.innerText;

        const nameText =
            nameCol.textContent ||
            nameCol.innerText;

        if (
            userText
                .toUpperCase()
                .includes(filter) ||
            nameText
                .toUpperCase()
                .includes(filter)
        ) {

            rows[i].style.display =
                "";

        } else {

            rows[i].style.display =
                "none";
        }
    }
}

/* ==================================================
   LICENSE EDIT
================================================== */

function quickEditLicense(
    id,
    key,
    name,
    total
) {

    const panel =
        document.getElementById(
            "license-panel"
        );

    if (panel)
        panel.classList.remove(
            "hidden"
        );

    document.getElementById(
        "form_row_id"
    ).value = id;

    document.getElementById(
        "form_software_key"
    ).value = key;

    document.getElementById(
        "form_software_name"
    ).value = name;

    document.getElementById(
        "form_total_licenses"
    ).value = total;

    document.getElementById(
        "license-form-title"
    ).innerHTML =
        "?? S?a License";

    document.getElementById(
        "submit-inventory-btn"
    ).innerHTML =
        "C?p Nh?t";

    document.getElementById(
        "cancel-edit-btn"
    ).style.display =
        "inline-flex";

    panel.scrollIntoView({
        behavior: "smooth"
    });
}

function resetLicenseForm() {

    document.getElementById(
        "form_row_id"
    ).value = "";

    document.getElementById(
        "form_software_key"
    ).value = "";

    document.getElementById(
        "form_software_name"
    ).value = "";

    document.getElementById(
        "form_total_licenses"
    ).value = "";

    document.getElementById(
        "license-form-title"
    ).innerHTML =
        "?? Nh?p Kho License";

    document.getElementById(
        "submit-inventory-btn"
    ).innerHTML =
        "Luu License";

    document.getElementById(
        "cancel-edit-btn"
    ).style.display =
        "none";
}

/* ==================================================
   USER MODAL
================================================== */

function openUserEditModal(
    sam,
    name,
    enabled,
    groupsStr
) {

    const modal =
        document.getElementById(
            "userEditModal"
        );

    document.getElementById(
        "modal_edit_username"
    ).value = sam;

    document.getElementById(
        "txt_modal_username"
    ).innerText = sam;

    document.getElementById(
        "txt_modal_fullname"
    ).innerText = name;

    document.getElementById(
        "modal_edit_status"
    ).value =
        enabled ? "true" : "false";

    document.getElementById(
        "dropdown_add_group_wrapper"
    ).style.display = "none";

    renderGroups(
        sam,
        groupsStr
    );

    fetchUserLicenses(
        sam
    );

    modal.style.display =
        "block";
}

function closeUserModal() {

    const modal =
        document.getElementById(
            "userEditModal"
        );

    if (modal)
        modal.style.display =
            "none";
}

/* ==================================================
   GROUPS
================================================== */

function renderGroups(
    username,
    groupsStr
) {

    const container =
        document.getElementById(
            "modal_badge_groups_container"
        );

    container.innerHTML = "";

    let groups =
        groupsStr
        ? groupsStr.split(",")
        : [];

    groups =
        groups
            .map(
                g => g.trim()
            )
            .filter(
                g => g.length > 0
            );

    if (
        groups.length === 0
    ) {

        container.innerHTML =
            "<div class='empty-state'>Không có Group</div>";

        return;
    }

    groups.forEach(group => {

        const div =
            document.createElement(
                "div"
            );

        div.className =
            "group-badge";

        div.innerHTML =
            `
            ${group}
            <span
                class="group-remove"
                onclick="ajaxRemoveUserFromGroup('${username}','${group}',this)">
                ×
            </span>
            `;

        container.appendChild(
            div
        );
    });
}

function toggleAddGroupDropdown() {

    const box =
        document.getElementById(
            "dropdown_add_group_wrapper"
        );

    box.style.display =
        box.style.display === "none"
        ? "block"
        : "none";
}

function ajaxRemoveUserFromGroup(
    username,
    groupName,
    element
) {

    if (
        !confirm(
            `Xóa ${username} kh?i group ${groupName}?`
        )
    )
        return;

    fetch(
        "/api/remove-user-group",
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                username,
                group: groupName
            })
        }
    )
    .then(r => r.json())
    .then(data => {

        if (
            data.status === "success"
        ) {

            element.parentElement.remove();

            showToast(
                "Ðã xóa kh?i group",
                "success"
            );

        } else {

            showToast(
                data.message,
                "danger"
            );
        }
    });
}

/* ==================================================
   LICENSE FETCH
================================================== */

function fetchUserLicenses(
    username
) {

    const container =
        document.getElementById(
            "modal_isolated_licenses_container"
        );

    container.innerHTML =
        "Ðang t?i...";

    fetch(
        `/api/user-licenses/${username}`
    )
    .then(r => r.json())
    .then(data => {

        container.innerHTML =
            "";

        if (
            !data.licenses ||
            data.licenses.length === 0
        ) {

            container.innerHTML =
                "<div class='empty-state'>Chua có license</div>";

            return;
        }

        data.licenses.forEach(
            item => {

                const div =
                    document.createElement(
                        "div"
                    );

                div.className =
                    "license-item";

                div.innerHTML =
                    `
                    <div>
                        <strong>${item.key}</strong>
                        <br>
                        S? lu?ng:
                        ${item.quantity}
                    </div>

                    <button
                        class="btn btn-danger btn-sm"
                        onclick="revokeLicenseDirect('${username}','${item.key}',${item.quantity},false)">
                        Thu H?i
                    </button>
                    `;

                container.appendChild(
                    div
                );
            }
        );
    });
}

/* ==================================================
   REVOKE LICENSE
================================================== */

function revokeLicenseDirect(
    username,
    licenseKey,
    currentQty,
    refresh
) {

    let qty =
        prompt(
            `Thu h?i bao nhiêu license?\nHi?n t?i: ${currentQty}`,
            currentQty
        );

    if (
        qty === null
    )
        return;

    qty = parseInt(qty);

    if (
        isNaN(qty) ||
        qty <= 0 ||
        qty > currentQty
    ) {

        alert(
            "S? lu?ng không h?p l?"
        );

        return;
    }

    fetch(
        "/api/revoke-license-direct",
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                username,
                key: licenseKey,
                quantity: qty
            })
        }
    )
    .then(r => r.json())
    .then(() => {

        showToast(
            "Thu h?i thành công",
            "success"
        );

        if (refresh) {

            location.reload();

        } else {

            fetchUserLicenses(
                username
            );
        }
    });
}

/* ==================================================
   DELETE LICENSE
================================================== */

function deleteLicenseWithAuth(
    rowId
) {

    currentDeleteId =
        rowId;

    document.getElementById(
        "passwordModal"
    ).style.display =
        "block";

    document.getElementById(
        "admin_pass_input"
    ).focus();
}

function closePasswordModal() {

    document.getElementById(
        "passwordModal"
    ).style.display =
        "none";

    document.getElementById(
        "admin_pass_input"
    ).value =
        "";
}

function submitDelete() {

    const pass =
        document.getElementById(
            "admin_pass_input"
        ).value;

    if (!pass) {

        alert(
            "Nh?p m?t kh?u Administrator"
        );

        return;
    }

    fetch(
        `/delete-software/${currentDeleteId}`,
        {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/json"
            },
            body: JSON.stringify({
                admin_pass: pass
            })
        }
    )
    .then(r => r.json())
    .then(data => {

        if (
            data.status === "success"
        ) {

            location.reload();

        } else {

            alert(
                data.message
            );

            closePasswordModal();
        }
    });
}

/* ==================================================
   MODAL OUTSIDE CLICK
================================================== */

window.onclick =
function(event) {

    const userModal =
        document.getElementById(
            "userEditModal"
        );

    const passwordModal =
        document.getElementById(
            "passwordModal"
        );

    if (
        event.target === userModal
    ) {

        closeUserModal();
    }

    if (
        event.target === passwordModal
    ) {

        closePasswordModal();
    }
};

/* ==================================================
   DOM READY
================================================== */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const savedTheme =
            localStorage.getItem("pv_theme") ||
            "light";

        document.documentElement.setAttribute(
            "data-theme",
            savedTheme
        );

        const btn =
            document.querySelector(
                ".theme-toggle"
            );

        if (btn) {

            btn.innerHTML =
                savedTheme === "dark"
                    ? "?? Night Mode"
                    : "?? Light Mode";
        }

        console.log(
            "PV Automation Portal V2 Loaded"
        );
    }
);