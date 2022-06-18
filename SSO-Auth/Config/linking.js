const ssoConfigLinking = {
  pluginUniqueId: "505ce9d1-d916-42fa-86ca-673ef241d7df",
  loadProviders: (view) => {
    const provider_list_id = "sso-provider-list";

    var provider_list = view.querySelector("#" + provider_list_id);
    provider_list.innerHTML = "";

    const currentUserId = ApiClient.getCurrentUserId();

    if (currentUserId) {
      ApiClient.fetch(
        {
          type: "GET",
          url: ApiClient.getUrl(`sso/OID/links/${currentUserId}`),
        },
        true
      ).then((resp) => {
        resp.json().then((x) => console.log(x));
      });
    }

    fetch(new Request(ApiClient.getUrl("sso/OID/GetNames"))).then((resp) => {
      resp.json().then((config_names) => {
        ssoConfigLinking.loadProviderList(provider_list, config_names, "oid");
      });
    });
    fetch(new Request(ApiClient.getUrl("sso/SAML/GetNames"))).then((resp) => {
      resp.json().then((config_names) => {
        ssoConfigLinking.loadProviderList(provider_list, config_names, "saml");
      });
    });
  },
  loadProviderList: (element, providers, provider_mode) => {
    providers.forEach((provider_name) => {
      var provider_link = document.createElement("a");

      provider_link.classList.add("raised");
      provider_link.classList.add("block");
      provider_link.classList.add("emby-button");

      //const provider_name_css = ssoConfigLinking.safeCSSId(provider_name);
      //provider_link.id = "sso-provider-" + provider_name_css;
      //provider_link.classList.add("sso-provider-" + provider_name_css);
      provider_link.classList.add("sso-provider");

      provider_link.text = provider_name;

      provider_link.href = ApiClient.getUrl(
        `/SSO/${provider_mode}/p/${provider_name}?isLinking=true`
      );

      element.appendChild(provider_link);
    });
  },
};

export default function (view) {
  ssoConfigLinking.loadProviders(view);
}
