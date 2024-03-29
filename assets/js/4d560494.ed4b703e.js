"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9585],{132:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>c,contentTitle:()=>i,default:()=>h,frontMatter:()=>l,metadata:()=>u,toc:()=>d});var a=t(4848),n=t(8453),s=t(7861),o=t(26);const l={id:"provider-terraform"},i="\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430",u={id:"tech-docs/terraform/provider-terraform",title:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430",description:"<Tabs",source:"@site/versioned_docs/version-v1.13.0/tech-docs/terraform/provider.mdx",sourceDirName:"tech-docs/terraform",slug:"/tech-docs/terraform/provider-terraform",permalink:"/sgroups/v1.13.0/tech-docs/terraform/provider-terraform",draft:!1,unlisted:!1,tags:[],version:"v1.13.0",frontMatter:{id:"provider-terraform"},sidebar:"techDocs",previous:{title:"GET /v1/sync/status",permalink:"/sgroups/v1.13.0/tech-docs/sgroups/api/v1/status"},next:{title:"\u0417\u0430\u043f\u0443\u0441\u043a",permalink:"/sgroups/v1.13.0/tech-docs/terraform/spec-terraform"}},c={},d=[];function p(e){const r={a:"a",code:"code",h1:"h1",p:"p",pre:"pre",...(0,n.R)(),...e.components};return(0,a.jsxs)(a.Fragment,{children:[(0,a.jsx)(r.h1,{id:"\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430-\u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430",children:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430"}),"\n",(0,a.jsxs)(s.A,{defaltValue:"bin",value:[{label:"bin",value:"bin"},{label:"source",value:"source"}],children:[(0,a.jsxs)(o.A,{value:"bin",children:[(0,a.jsxs)("div",{children:[(0,a.jsxs)(r.p,{children:["\u041f\u0435\u0440\u0435\u0434 \u0440\u0430\u0437\u0432\u0435\u0440\u0442\u044b\u0432\u0430\u043d\u0438\u0435\u043c \u0443\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0443 \u0432\u0430\u0441 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d ",(0,a.jsx)(r.a,{href:"https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli",children:"terraform"}),":"]}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",children:"terraform -v\n"})}),(0,a.jsxs)(r.p,{children:["\u0414\u0430\u043b\u0435\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u043e\u0439 \u0443\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u0443\u043a\u0430\u0437\u0430\u043b\u0438 \u0432\u0435\u0440\u0441\u0438\u044e,\n\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0432 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u0443\u044e ",(0,a.jsx)(r.code,{children:"VERSION"})," \u0431\u0435\u0437 \u0441\u0438\u043c\u0432\u043e\u043b\u0430 'v', \u0430 \u0442\u0430\u043a\u0436\u0435 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u0435 ",(0,a.jsx)(r.code,{children:"OS"})," \u0438 ",(0,a.jsx)(r.code,{children:"ARCH"}),"."]})]}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",metastring:"title='Environment setup'",children:"export VERSION=1.9.1\nexport OS=linux\nexport ARCH=amd64\nexport GIT=https://github.com/H-BF/sgroups/releases/download/v${VERSION}\nexport RELEASE_NAME=terraform-provider-sgroups\nexport PLUGIN_PATH=~/.terraform.d/plugins/registry.terraform.io/sgroups\nexport PROVIDER_PATH=${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}/${RELEASE_NAME}_v${VERSION}\nmkdir -p ${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}\n"})}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",metastring:"title='Install provider'",children:"wget -O ${PROVIDER_PATH} ${GIT}/${RELEASE_NAME}\nchmod +x ${PROVIDER_PATH}\n"})}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",metastring:"title='Terraform setup'",children:'cat <<EOF >> ~/.terraformrc\nplugin_cache_dir = "${HOME}/.terraform.d/plugin-cache"\ndisable_checkpoint = true\nEOF\n'})})]}),(0,a.jsxs)(o.A,{value:"source",children:[" ",(0,a.jsx)("div",{children:(0,a.jsxs)(r.p,{children:["\u041f\u0435\u0440\u0435\u0434 \u0440\u0430\u0437\u0432\u0435\u0440\u0442\u044b\u0432\u0430\u043d\u0438\u0435\u043c \u0443\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u0443\u043a\u0430\u0437\u0430\u043b\u0438 \u0432\u0435\u0440\u0441\u0438\u044e, \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0432 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u0443\u044e ",(0,a.jsx)(r.code,{children:"VERSION"})," \u0431\u0435\u0437 \u0441\u0438\u043c\u0432\u043e\u043b\u0430 'v', \u0430\n\u0442\u0430\u043a\u0436\u0435 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u0435 ",(0,a.jsx)(r.code,{children:"OS"})," \u0438 ",(0,a.jsx)(r.code,{children:"ARCH"}),"."]})}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",metastring:"title='Environment setup'",children:"export VERSION=1.9.1\nexport OS=linux\nexport ARCH=amd64\nexport RELEASE_NAME=terraform-provider-sgroups\nexport PLUGIN_PATH=~/.terraform.d/plugins/registry.terraform.io/sgroups\nexport PROVIDER_PATH=${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}/${RELEASE_NAME}_v${VERSION}\nmkdir -p ${PLUGIN_PATH}/${VERSION}/${OS}_${ARCH}\n"})}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",metastring:"title='Build provider'",children:"git clone https://github.com/H-BF/sgroups\ncd sgroups\nmake sgroups-tf-v2\ncp bin/${RELEASE_NAME} ${PROVIDER_PATH}\nchmod +x ${PROVIDER_PATH}\n"})}),(0,a.jsx)(r.pre,{children:(0,a.jsx)(r.code,{className:"language-bash",metastring:"title='Terraform setup'",children:'cat <<EOF >> ~/.terraformrc\nplugin_cache_dir = "${HOME}/.terraform.d/plugin-cache"\ndisable_checkpoint = true\nEOF\n'})})]})]})]})}function h(e={}){const{wrapper:r}={...(0,n.R)(),...e.components};return r?(0,a.jsx)(r,{...e,children:(0,a.jsx)(p,{...e})}):p(e)}},26:(e,r,t)=>{t.d(r,{A:()=>o});t(6540);var a=t(4164);const n={tabItem:"tabItem_Ymn6"};var s=t(4848);function o(e){let{children:r,hidden:t,className:o}=e;return(0,s.jsx)("div",{role:"tabpanel",className:(0,a.A)(n.tabItem,o),hidden:t,children:r})}},7861:(e,r,t)=>{t.d(r,{A:()=>I});var a=t(6540),n=t(4164),s=t(3104),o=t(6347),l=t(205),i=t(7485),u=t(1682),c=t(9466);function d(e){return a.Children.toArray(e).filter((e=>"\n"!==e)).map((e=>{if(!e||(0,a.isValidElement)(e)&&function(e){const{props:r}=e;return!!r&&"object"==typeof r&&"value"in r}(e))return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)}))?.filter(Boolean)??[]}function p(e){const{values:r,children:t}=e;return(0,a.useMemo)((()=>{const e=r??function(e){return d(e).map((e=>{let{props:{value:r,label:t,attributes:a,default:n}}=e;return{value:r,label:t,attributes:a,default:n}}))}(t);return function(e){const r=(0,u.X)(e,((e,r)=>e.value===r.value));if(r.length>0)throw new Error(`Docusaurus error: Duplicate values "${r.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`)}(e),e}),[r,t])}function h(e){let{value:r,tabValues:t}=e;return t.some((e=>e.value===r))}function m(e){let{queryString:r=!1,groupId:t}=e;const n=(0,o.W6)(),s=function(e){let{queryString:r=!1,groupId:t}=e;if("string"==typeof r)return r;if(!1===r)return null;if(!0===r&&!t)throw new Error('Docusaurus error: The <Tabs> component groupId prop is required if queryString=true, because this value is used as the search param name. You can also provide an explicit value such as queryString="my-search-param".');return t??null}({queryString:r,groupId:t});return[(0,i.aZ)(s),(0,a.useCallback)((e=>{if(!s)return;const r=new URLSearchParams(n.location.search);r.set(s,e),n.replace({...n.location,search:r.toString()})}),[s,n])]}function f(e){const{defaultValue:r,queryString:t=!1,groupId:n}=e,s=p(e),[o,i]=(0,a.useState)((()=>function(e){let{defaultValue:r,tabValues:t}=e;if(0===t.length)throw new Error("Docusaurus error: the <Tabs> component requires at least one <TabItem> children component");if(r){if(!h({value:r,tabValues:t}))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${r}" but none of its children has the corresponding value. Available values are: ${t.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);return r}const a=t.find((e=>e.default))??t[0];if(!a)throw new Error("Unexpected error: 0 tabValues");return a.value}({defaultValue:r,tabValues:s}))),[u,d]=m({queryString:t,groupId:n}),[f,b]=function(e){let{groupId:r}=e;const t=function(e){return e?`docusaurus.tab.${e}`:null}(r),[n,s]=(0,c.Dv)(t);return[n,(0,a.useCallback)((e=>{t&&s.set(e)}),[t,s])]}({groupId:n}),v=(()=>{const e=u??f;return h({value:e,tabValues:s})?e:null})();(0,l.A)((()=>{v&&i(v)}),[v]);return{selectedValue:o,selectValue:(0,a.useCallback)((e=>{if(!h({value:e,tabValues:s}))throw new Error(`Can't select invalid tab value=${e}`);i(e),d(e),b(e)}),[d,b,s]),tabValues:s}}var b=t(2303);const v={tabList:"tabList__CuJ",tabItem:"tabItem_LNqP"};var g=t(4848);function x(e){let{className:r,block:t,selectedValue:a,selectValue:o,tabValues:l}=e;const i=[],{blockElementScrollPositionUntilNextRender:u}=(0,s.a_)(),c=e=>{const r=e.currentTarget,t=i.indexOf(r),n=l[t].value;n!==a&&(u(r),o(n))},d=e=>{let r=null;switch(e.key){case"Enter":c(e);break;case"ArrowRight":{const t=i.indexOf(e.currentTarget)+1;r=i[t]??i[0];break}case"ArrowLeft":{const t=i.indexOf(e.currentTarget)-1;r=i[t]??i[i.length-1];break}}r?.focus()};return(0,g.jsx)("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,n.A)("tabs",{"tabs--block":t},r),children:l.map((e=>{let{value:r,label:t,attributes:s}=e;return(0,g.jsx)("li",{role:"tab",tabIndex:a===r?0:-1,"aria-selected":a===r,ref:e=>i.push(e),onKeyDown:d,onClick:c,...s,className:(0,n.A)("tabs__item",v.tabItem,s?.className,{"tabs__item--active":a===r}),children:t??r},r)}))})}function E(e){let{lazy:r,children:t,selectedValue:n}=e;const s=(Array.isArray(t)?t:[t]).filter(Boolean);if(r){const e=s.find((e=>e.props.value===n));return e?(0,a.cloneElement)(e,{className:"margin-top--md"}):null}return(0,g.jsx)("div",{className:"margin-top--md",children:s.map(((e,r)=>(0,a.cloneElement)(e,{key:r,hidden:e.props.value!==n})))})}function A(e){const r=f(e);return(0,g.jsxs)("div",{className:(0,n.A)("tabs-container",v.tabList),children:[(0,g.jsx)(x,{...e,...r}),(0,g.jsx)(E,{...e,...r})]})}function I(e){const r=(0,b.A)();return(0,g.jsx)(A,{...e,children:d(e.children)},String(r))}}}]);