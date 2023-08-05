const ssoConfigLinking = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  loadProviders: (view) => {
    const provider_list_id = "sso-provider-list";
    const provider_list_saml_id = `${provider_list_id}-saml`;
    const provider_list_oid_id = `${provider_list_id}-oid`;

    const provider_list_saml = view.querySelector(`#${provider_list_saml_id}`);
    const provider_list_oid = view.querySelector(`#${provider_list_oid_id}`);
    provider_list_saml.innerHTML = "";
    provider_list_oid.innerHTML = "";

    fetch(new Request(ApiClient.getUrl("sso/OID/GetNames"))).then((resp) => {
      resp.json().then((config_names) => {
        ssoConfigLinking.loadProviderList(
          provider_list_oid,
          config_names,
          "oid",
        );
      });
    });
    fetch(new Request(ApiClient.getUrl("sso/SAML/GetNames"))).then((resp) => {
      resp.json().then((config_names) => {
        ssoConfigLinking.loadProviderList(
          provider_list_saml,
          config_names,
          "saml",
        );
      });
    });
  },
  loadProviderList: (container, providers, provider_mode) => {
    providers.forEach((provider_name) => {
      var provider_config = document.createElement("div");
      provider_config.classList.add("sso-provider-links-container");
      provider_config.setAttribute("data-id", provider_name);

      provider_config.innerHTML = `
      <label
        class="inputLabel inputLabelUnfocused sso-provider-link-title"
      >${provider_name}
      </label>
      <a
        class="fab emby-button sso-provider-add-link"
      >
        <span class="material-icons add" aria-hidden="true"></span>
      </a>
      <div
        class="sso-provider-existing-links-container"
        data-provider="${provider_name}"
      ></div>
      `;
      var add_provider = provider_config.querySelector(
        ".sso-provider-add-link",
      );

      //const provider_name_css = ssoConfigLinking.safeCSSId(provider_name);
      //provider_link.id = "sso-provider-" + provider_name_css;
      //provider_link.classList.add("sso-provider-" + provider_name_css);
      add_provider.classList.add("sso-provider");

      add_provider.href = ApiClient.getUrl(
        `/SSO/${provider_mode}/p/${provider_name}?isLinking=true`,
      );

      container.appendChild(provider_config);
    });

    const currentUserId = ApiClient.getCurrentUserId();

    if (currentUserId) {
      ApiClient.fetch(
        {
          type: "GET",
          url: ApiClient.getUrl(`sso/${provider_mode}/links/${currentUserId}`),
        },
        true,
      ).then((resp) => {
        resp.json().then((provider_map) => {
          console.log({ provider_map, currentUserId });

          Object.keys(provider_map).forEach((provider_name) => {
            const provider_container = container.querySelector(
              `.sso-provider-existing-links-container[data-provider="${provider_name}"]`,
            );
            ssoConfigLinking.populateExistingLinks(
              provider_container,
              provider_mode,
              provider_name,
              provider_map[provider_name],
            );
          });
        });
      });
    }
  },

  populateExistingLinks: (
    container,
    provider_mode,
    provider_name,
    canonical_names,
  ) => {
    container
      .querySelectorAll(".sso-provider-link-checkbox-wrapper")
      .forEach((e) => e.remove());

    const checkboxes = canonical_names.map((canonical_name) => {
      var out = document.createElement("label");
      out.classList.add("sso-provider-link-checkbox-wrapper");
      out.classList.add("checkbox-wrapper");
      out.innerHTML = `
        <input
          is="emby-checkbox"
          class="sso-link-checkbox"
          data-id="${canonical_name}"
          data-mode="${provider_mode}"
          data-provider="${provider_name}"
          type="checkbox"
        />
        <span class="checkbox-label">${canonical_name}</span>
      `;
      return out;
    });

    checkboxes.forEach((e) => {
      container.appendChild(e);
    });
  },

  handleDeleteButtonPressed: (evt, view) => {
    if (evt.target.disabled) return;

    const currentUserId = ApiClient.getCurrentUserId();
    if (!currentUserId) return;

    const delete_requests = [...view.querySelectorAll(".sso-link-checkbox")]
      .filter((checkbox_link) => {
        const canonical_name = checkbox_link.getAttribute("data-id");
        const provider_name = checkbox_link.getAttribute("data-provider");
        const provider_mode = checkbox_link.getAttribute("data-mode");

        if (![canonical_name, provider_name, provider_mode].every((e) => e)) {
          return false;
        }

        if (!checkbox_link.checked) {
          return false;
        }

        return true;
      })
      .map((checked_link) => {
        const canonical_name = checked_link.getAttribute("data-id");
        const provider_name = checked_link.getAttribute("data-provider");
        const provider_mode = checked_link.getAttribute("data-mode");

        return ApiClient.fetch({
          type: "DELETE",
          url: ApiClient.getUrl(
            `sso/${provider_mode}/link/${provider_name}/${currentUserId}/${canonical_name}`,
          ),
        });
      });

    Promise.all(delete_requests).then((values) => {
      console.log({ message: "Delete requests handled", values });
      window.location.reload();
    });
  },
};

export default function (view) {
  ssoConfigLinking.loadProviders(view);

  view.querySelector("#enable-delete").addEventListener("change", (e) => {
    view.querySelector("#btn-delete-selected-links").disabled =
      !e.target.checked;
  });

  view
    .querySelector("#btn-delete-selected-links")
    .addEventListener("click", (e) =>
      ssoConfigLinking.handleDeleteButtonPressed(e, view),
    );
}
