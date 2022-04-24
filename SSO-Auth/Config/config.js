const ssoConfigurationPage = {
    pluginUniqueId: '505ce9d1-d916-42fa-86ca-673ef241d7df',
    brandingConfigKey : 'branding',
    loadConfiguration: (page) => {
        ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then((config) => {

            ssoConfigurationPage.populateProviders(page, config.OidConfigs);


        });
    },
    populateProviders: (page, providers) => {

        // Clear providers in case there are out of date ones
        page.querySelector("#selectProvider").querySelectorAll("option").forEach(option => {
            option.remove();
        });

        // Add providers as options for the selector

        Object.keys(providers).forEach(
            ( provider_name ) => {
                var choice = new Option(
                    provider_name,
                    provider_name
                    );
                    
                    page.querySelector("#selectProvider").appendChild(choice);
            });
    },
    listArgumentsByType : (page) => {
        const json_fields = ["EnabledFolders", "FolderRoleMapping", "Roles", "AdminRoles"];

        const new_oidc_provider_form = page.querySelector("#sso-new-oidc-provider");

        const text_fields = [...new_oidc_provider_form.querySelectorAll("input[type='text']")].map( e => e.id).filter( id => ! json_fields.includes(id));

        const check_fields = [...new_oidc_provider_form.querySelectorAll("input[type='checkbox']")].map( e => e.id);

        const output = { json_fields, text_fields, check_fields};

        return output;

    }, 
    loadProvider : (page, provider_name) => {

        ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => { 
            var provider = config.OidConfigs[provider_name] || {};

            const form_elements = ssoConfigurationPage.listArgumentsByType(page);

            page.querySelector("#OidProviderName").value = provider_name;
    
    
            form_elements.text_fields.forEach(( id ) => {
                if (provider[id]) page.querySelector("#"+id).value = provider[id];
            });
    
            form_elements.json_fields.forEach( (id ) => {
                if (provider[id]) page.querySelector("#"+id).value = JSON.stringify(provider[id]);
            });
    
            form_elements.check_fields.forEach( ( id ) => {
                if (provider[id]) page.querySelector("#"+id).checked = provider[id];
            });

        });

    },
    deleteProvider : (page, provider_name) => {
        return new Promise( (resolve ) => {
            ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => {
                if (!config.OidConfigs.hasOwnProperty(provider_name)) {
                    resolve();
                    return;
                }
                
                delete config.OidConfigs[provider_name];
                ApiClient.updatePluginConfiguration(ssoConfigurationPage.pluginUniqueId, config).then(function (result) {
                    Dashboard.processPluginConfigurationUpdateResult(result);
                    ssoConfigurationPage.loadConfiguration(page);

                    Dashboard.alert('Provider removed');

                    resolve();
                });
                
            });
        });

    },
    saveProvider : (page, provider_name) => {
        return new Promise( (resolve ) => {
            const form_elements = ssoConfigurationPage.listArgumentsByType(page);

            ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => {
                var current_config = {};
                if (config.OidConfigs.hasOwnProperty(provider_name)) {
                    current_config = config.OidConfigs[provider_name];
                }

                form_elements.text_fields.forEach(( id ) => {
                    const value = page.querySelector("#"+id).value;
                    if (value) current_config[id] = page.querySelector("#"+id).value;
                });

                form_elements.json_fields.forEach( (id ) => {
                    const value = page.querySelector("#"+id).value;
                    if (value) current_config[id] = JSON.parse(value);
                });

                form_elements.check_fields.forEach( ( id ) => {
                    current_config[id] = page.querySelector("#"+id).checked;
                });

                config.OidConfigs[provider_name] = current_config;

                ApiClient.updatePluginConfiguration(ssoConfigurationPage.pluginUniqueId, config).then(function (result) {
                    Dashboard.processPluginConfigurationUpdateResult(result);
                    ssoConfigurationPage.loadConfiguration(page);
                    ssoConfigurationPage.loadProvider(page, provider_name);


                    page.querySelector("#selectProvider").value = provider_name;
                    Dashboard.alert('Settings saved.');
                    resolve();

            });
    
    

        });
    });
 
    },
    loadBranding: (page) => {
        ApiClient.getNamedConfiguration(ssoConfigurationPage.brandingConfigKey).then(function (config) {
            page.querySelector('#txtLoginDisclaimerBefore').value = config.LoginDisclaimer || '';
            page.querySelector('#txtCustomCssBefore').value = config.CustomCss || '';
        });
        ssoConfigurationPage.updateBranding(page);
    },
    // https://stackoverflow.com/a/43693571
    safeCSSId: (identifier) => {
        return encodeURIComponent(identifier)
            .toLowerCase()
            .replace(/\.|%[0-9a-z]{2}/gi, '');
    },
    updateBrandingDisclaimer: (page, config) => {
        const provider_list_id = "sso-provider-list";
        var html_branding = document.createElement("div");

        html_branding.innerHTML = page.querySelector('#txtLoginDisclaimerBefore').value;

        var provider_list = html_branding.querySelector('#'+provider_list_id);

        if (! provider_list ) {
            provider_list = document.createElement("div");
            provider_list.id = provider_list_id;

            html_branding.prepend(provider_list);
        }

        provider_list.innerHTML = '';

        const providers = config.OidConfigs;
        Object.keys(providers).forEach(
            ( provider_name ) => {
                var provider_link = document.createElement("a");
                
                provider_link.classList.add("raised");
                provider_link.classList.add("block");
                provider_link.classList.add("emby-button");
                

                const provider_name_css = ssoConfigurationPage.safeCSSId(provider_name);

                provider_link.classList.add("sso-provider-"+provider_name_css);
                provider_link.classList.add("sso-provider");
                provider_link.id = "sso-provider-"+provider_name_css;
                provider_link.text = provider_name;

                provider_link.href = window.location.protocol + '//' + window.location.host + "/SSO/OID/p/" + provider_name;
                    
                provider_list.appendChild(provider_link);
            });
        page.querySelector("#txtLoginDisclaimerAfter").value = html_branding.innerHTML;

    },
    updateBrandingCss: (page, config) => {
        var current_branding_css = new CSSStyleSheet();
        var current_css_text = page.querySelector('#txtCustomCssBefore').value;
        current_branding_css.replaceSync(current_css_text);
        const current_rules = [...current_branding_css.rules];

        const new_rules = {
            "a.raised.emby-button" : `{
                padding: 0.9em 1em;
                color: inherit !important;
            }`,
            ".disclaimerContainer" : `{
                display: block;
            }`,
            ".sso-provider" : `{
                /* Configure me later */
            }`,
        }

        Object.keys(new_rules).forEach((selector) => {
            const rule_text = "".concat(selector, ' ', new_rules[selector], '\n');
            if (!current_rules.map(x => x.selectorText).includes(selector)) {
                current_css_text = current_css_text.concat("\n", rule_text);
            }
        });

        page.querySelector("#txtCustomCssAfter").value = current_css_text;

    },
    updateBranding: (page) => {
        ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(config => {
            ssoConfigurationPage.updateBrandingDisclaimer(page, config);
            ssoConfigurationPage.updateBrandingCss(page, config);

        });
    },

    applyBranding: (page) => {
        ApiClient.getNamedConfiguration(ssoConfigurationPage.brandingConfigKey).then(function(brandingConfig) {
            brandingConfig.LoginDisclaimer = page.querySelector('#txtLoginDisclaimerAfter').value;
            brandingConfig.CustomCss = page.querySelector('#txtCustomCssAfter').value;

            ApiClient.updateNamedConfiguration(ssoConfigurationPage.brandingConfigKey, brandingConfig).then(function () {
                Dashboard.processServerConfigurationUpdateResult();
            });
        });
    },
    textAreaStyling: `
    .emby-textarea {
        display: block;
        margin: 0;
        margin-bottom: 0 !important;
    
        /* Remove select styling */
    
        /* Font size must the 16px or larger to prevent iOS page zoom on focus */
        font-size: inherit;
    
        /* General select styles: change as needed */
        font-family: inherit;
        font-weight: inherit;
        color: inherit;
        padding: 0.35em 0.25em;
    
        /* Prevent padding from causing width overflow */
        box-sizing: border-box;
        outline: none !important;
        -webkit-tap-highlight-color: rgba(0, 0, 0, 0);
        width: 100%;
    }
    
    .emby-textarea::-moz-focus-inner {
        border: 0;
    }
    
    .textareaLabel {
        display: inline-block;
        transition: all 0.2s ease-out;
        margin-bottom: 0.25em;
    }
    
    .emby-textarea + .fieldDescription {
        margin-top: 0.25em;
    }
    `,
    // Is this the only way to add css to my page? probably not, right?
    addTextAreaStyle: (view) => {
        var style = document.createElement("style");
        style.type = 'text/css';
        style.textContent = ssoConfigurationPage.textAreaStyling;

        view.appendChild(style);

    },

};

export default function (view) {
    ssoConfigurationPage.loadConfiguration(view);


    ssoConfigurationPage.addTextAreaStyle(view);

    ssoConfigurationPage.listArgumentsByType(view);
    ssoConfigurationPage.loadBranding(view);
    view.querySelector("#SaveProvider")
        .addEventListener("click", e => {

            const target_provider = view.querySelector("#OidProviderName").value;

            ssoConfigurationPage.saveProvider(view, target_provider);

            e.preventDefault();
            return false;

        });

    view.querySelector("#LoadProvider")
        .addEventListener("click", e => {

            const target_provider = view.querySelector("#selectProvider").value;

            ssoConfigurationPage.loadProvider(view, target_provider);

            e.preventDefault();
            return false;

        });

    view.querySelector("#DeleteProvider")
        .addEventListener("click", e => {

            const target_provider = view.querySelector("#selectProvider").value;

            ssoConfigurationPage.deleteProvider(view, target_provider);

            e.preventDefault();
            return false;

        });

    view.querySelector("#ApplyBranding")
        .addEventListener("click", e => {
            ssoConfigurationPage.applyBranding(view);

            e.preventDefault();
            return false;

        });

        


    
};



