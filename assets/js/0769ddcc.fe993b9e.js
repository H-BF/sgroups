"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[5765],{5897:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>i,contentTitle:()=>a,default:()=>d,frontMatter:()=>l,metadata:()=>c,toc:()=>o});var n=r(4848),s=r(8453);r(7861),r(26);const l={id:"tls-configuration-agent"},a="\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430",c={id:"tech-docs/to-nft/tls-configuration-agent",title:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430",description:"\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 TLS (Transport Layer Security) \u043d\u0430 hbf-\u0430\u0433\u0435\u043d\u0442\u0435 \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u0435\u0442 \u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u043c\u0435\u0436\u0434\u0443 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u043c \u0438 \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u043c,",source:"@site/versioned_docs/version-v1.15.0/tech-docs/to-nft/tls-configuration-agent.mdx",sourceDirName:"tech-docs/to-nft",slug:"/tech-docs/to-nft/tls-configuration-agent",permalink:"/sgroups/tech-docs/to-nft/tls-configuration-agent",draft:!1,unlisted:!1,tags:[],version:"v1.15.0",frontMatter:{id:"tls-configuration-agent"},sidebar:"techDocs",previous:{title:"\u041c\u043e\u043d\u0438\u0442\u043e\u0440\u0438\u043d\u0433",permalink:"/sgroups/tech-docs/to-nft/monitoring"},next:{title:"IPSet",permalink:"/sgroups/tech-docs/to-nft/nftables/ipset"}},i={},o=[{value:"\u0428\u0430\u0433\u0438 \u043f\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 TLS",id:"\u0448\u0430\u0433\u0438-\u043f\u043e-\u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435-tls",level:2}];function u(e){const t={code:"code",h1:"h1",h2:"h2",p:"p",pre:"pre",...(0,s.R)(),...e.components};return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsx)(t.h1,{id:"\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430",children:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430"}),"\n",(0,n.jsx)("div",{children:(0,n.jsx)(t.p,{children:"\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 TLS (Transport Layer Security) \u043d\u0430 hbf-\u0430\u0433\u0435\u043d\u0442\u0435 \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u0435\u0442 \u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u043c\u0435\u0436\u0434\u0443 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u043c \u0438 \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u043c,\n\u0447\u0442\u043e \u043f\u043e\u0432\u044b\u0448\u0430\u0435\u0442 \u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u044c \u043f\u0435\u0440\u0435\u0434\u0430\u0432\u0430\u0435\u043c\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445. \u0412 \u044d\u0442\u043e\u0439 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u0438 \u043e\u043f\u0438\u0441\u0430\u043d \u043f\u0440\u043e\u0446\u0435\u0441\u0441 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 TLS \u043d\u0430 hbf-\u0430\u0433\u0435\u043d\u0442\u0435, \u0432\u043a\u043b\u044e\u0447\u0430\u044f\n\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u0435 \u043f\u0440\u0435\u0434\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u043e\u043d\u043d\u043e\u0433\u043e \u0444\u0430\u0439\u043b\u0430."})}),"\n",(0,n.jsxs)("div",{children:[(0,n.jsx)(t.p,{children:"\u041f\u0440\u0435\u0436\u0434\u0435 \u0447\u0435\u043c \u043f\u0440\u0438\u0441\u0442\u0443\u043f\u0438\u0442\u044c \u043a \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 TLS, \u0443\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0443 \u0432\u0430\u0441 \u0435\u0441\u0442\u044c:"}),(0,n.jsxs)("ul",{children:[(0,n.jsx)("li",{children:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u044b\u0439 hbf-\u0430\u0433\u0435\u043d\u0442"}),(0,n.jsx)("li",{children:"\u0412\u043a\u043b\u044e\u0447\u0435\u043d \u0438 \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043d TLS \u043d\u0430 hbf-\u0441\u0435\u0440\u0432\u0435\u0440\u0435"}),(0,n.jsx)("li",{children:"\u0421\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 SSL \u0438 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0439 \u043f\u0440\u0438\u0432\u0430\u0442\u043d\u044b\u0439 \u043a\u043b\u044e\u0447. \u0415\u0441\u043b\u0438 \u0443 \u0432\u0430\u0441 \u0438\u0445 \u043d\u0435\u0442, \u0432\u044b \u043c\u043e\u0436\u0435\u0442\u0435 \u043f\u043e\u043b\u0443\u0447\u0438\u0442\u044c \u0438\u0445 \u0443 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u043e\u043d\u043d\u043e\u0433\u043e\n\u0446\u0435\u043d\u0442\u0440\u0430 (CA) \u0438\u043b\u0438 \u0441\u043e\u0437\u0434\u0430\u0442\u044c \u0441\u0430\u043c\u043e\u043f\u043e\u0434\u043f\u0438\u0441\u0430\u043d\u043d\u044b\u0439 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u0434\u043b\u044f \u0442\u0435\u0441\u0442\u043e\u0432\u044b\u0445 \u0446\u0435\u043b\u0435\u0439."})]})]}),"\n",(0,n.jsx)(t.h2,{id:"\u0448\u0430\u0433\u0438-\u043f\u043e-\u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435-tls",children:"\u0428\u0430\u0433\u0438 \u043f\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 TLS"}),"\n",(0,n.jsxs)("div",{children:[(0,n.jsx)(t.p,{children:"\u0421\u043e\u0437\u0434\u0430\u0439\u0442\u0435 \u0434\u0438\u0440\u0435\u043a\u0442\u043e\u0440\u0438\u044e \u0434\u043b\u044f \u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f \u0432\u0430\u0448\u0438\u0445 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0432 \u0438 \u043a\u043b\u044e\u0447\u0435\u0439, \u0435\u0441\u043b\u0438 \u043e\u043d\u0430 \u0435\u0449\u0435 \u043d\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442:"}),(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"sudo mkdir -p /etc/ssl/certs\nsudo mkdir -p /etc/ssl/private\n"})})]}),"\n",(0,n.jsxs)("div",{children:[(0,n.jsx)(t.p,{children:"\u0421\u043a\u043e\u043f\u0438\u0440\u0443\u0439\u0442\u0435 \u0432\u0430\u0448 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u0438 \u043f\u0440\u0438\u0432\u0430\u0442\u043d\u044b\u0439 \u043a\u043b\u044e\u0447 \u0432 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0435 \u0434\u0438\u0440\u0435\u043a\u0442\u043e\u0440\u0438\u0438. \u041d\u0430\u043f\u0440\u0438\u043c\u0435\u0440:"}),(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"sudo cp /path/to/your/cert-file.pem /etc/ssl/certs/\nsudo cp /path/to/your/key-file.pem /etc/ssl/private/\n"})})]}),"\n",(0,n.jsxs)("div",{children:[(0,n.jsx)(t.p,{children:"\u041e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 \u0444\u0430\u0439\u043b \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 hbf-\u0430\u0433\u0435\u043d\u0442\u0430 \u0434\u043b\u044f \u0440\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u044f:"}),(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:"sudo nano /etc/cmd/sgroups/app-config.go\n"})}),(0,n.jsx)(t.p,{children:"\u0414\u0430\u043b\u0435\u0435 \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0438\u0442\u044c \u0441\u0435\u043a\u0446\u0438\u044e \u0434\u043b\u044f TLS:"}),(0,n.jsx)(t.pre,{children:(0,n.jsx)(t.code,{className:"language-bash",children:'authn:\n   type: tls\n   tls:\n   \tkey-file: "/etc/ssl/private/key-file.pem"\n   \tcert-file: "/etc/ssl/certs/cert-file.pem"\n   \t\tclient:\n   \t\t\tverify: skip\n   \t\t\tca-files: ["file1.pem", "file2.pem", ...]\n'})}),(0,n.jsxs)("p",{children:[(0,n.jsx)(t.code,{children:"type"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,n.jsx)(t.code,{children:"none"})," \u0438\u043b\u0438 ",(0,n.jsx)(t.code,{children:"tls"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,n.jsx)(t.code,{children:"none"})," tls \u043e\u0442\u043a\u043b\u044e\u0447\u0435\u043d, \u043f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,n.jsx)(t.code,{children:"tls"})," tls \u0432\u043a\u043b\u044e\u0447\u0435\u043d."]}),(0,n.jsxs)("p",{children:[(0,n.jsx)(t.code,{children:"key-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,n.jsx)(t.code,{children:"/etc/ssl/private/key-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,n.jsx)(t.code,{children:"./../key-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u043a\u043b\u044e\u0447\u0430."]}),(0,n.jsxs)("p",{children:[(0,n.jsx)(t.code,{children:"cert-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,n.jsx)(t.code,{children:"/etc/ssl/certs/cert-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,n.jsx)(t.code,{children:"./../cert-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u0430."]}),(0,n.jsxs)("p",{children:[(0,n.jsx)(t.code,{children:"verify"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,n.jsx)(t.code,{children:"skip"}),", ",(0,n.jsx)(t.code,{children:"cert-required"})," \u0438\u043b\u0438 ",(0,n.jsx)(t.code,{children:"verify"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,n.jsx)(t.code,{children:"skip"})," \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u0442\u0441\u044f, \u043f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,n.jsx)(t.code,{children:"cert-required"})," \u043e\u0442 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043d\u0430\u043b\u0438\u0447\u0438\u0435 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0432, \u043d\u043e \u0441\u043e \u0441\u0442\u043e\u0440\u043e\u043d\u044b \u0441\u0435\u0440\u0432\u0435\u043d\u0430 \u0434\u0430\u043d\u043d\u044b\u0435 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u044b \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u044e\u0442\u0441\u044f,\n\u043f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438 ",(0,n.jsx)(t.code,{children:"verify"})," \u0432\u043a\u043b\u044e\u0447\u0430\u0435\u0442\u0441\u044f \u0440\u0435\u0436\u0438\u043c mTLS, \u043a\u043e\u0433\u0434\u0430 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c \u0438 \u043f\u0440\u043e\u0438\u0441\u0445\u043e\u0434\u0438\u0442 \u0435\u0433\u043e \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430."]}),(0,n.jsxs)("p",{children:[(0,n.jsx)(t.code,{children:"ca-files"})," - \u041f\u0440\u0438 \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u043d\u043e\u043c \u0440\u0435\u0436\u0438\u043c\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0430 ",(0,n.jsx)(t.code,{children:"verify: verify"})," \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a certificates authorities \u0441 \u0443\u043a\u0430\u0437\u0430\u043d\u0438\u0435\u043c \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0433\u043e \u0438\u043b\u0438 \u043f\u043e\u043b\u043d\u043e\u0433\u043e \u043f\u0443\u0442\u0438 \u043a \u0444\u0430\u0439\u043b\u0430\u043c."]})]})]})}function d(e={}){const{wrapper:t}={...(0,s.R)(),...e.components};return t?(0,n.jsx)(t,{...e,children:(0,n.jsx)(u,{...e})}):u(e)}},26:(e,t,r)=>{r.d(t,{A:()=>a});r(6540);var n=r(4164);const s={tabItem:"tabItem_Ymn6"};var l=r(4848);function a(e){let{children:t,hidden:r,className:a}=e;return(0,l.jsx)("div",{role:"tabpanel",className:(0,n.A)(s.tabItem,a),hidden:r,children:t})}},7861:(e,t,r)=>{r.d(t,{A:()=>k});var n=r(6540),s=r(4164),l=r(3104),a=r(6347),c=r(205),i=r(7485),o=r(1682),u=r(9466);function d(e){return n.Children.toArray(e).filter((e=>"\n"!==e)).map((e=>{if(!e||(0,n.isValidElement)(e)&&function(e){const{props:t}=e;return!!t&&"object"==typeof t&&"value"in t}(e))return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)}))?.filter(Boolean)??[]}function h(e){const{values:t,children:r}=e;return(0,n.useMemo)((()=>{const e=t??function(e){return d(e).map((e=>{let{props:{value:t,label:r,attributes:n,default:s}}=e;return{value:t,label:r,attributes:n,default:s}}))}(r);return function(e){const t=(0,o.X)(e,((e,t)=>e.value===t.value));if(t.length>0)throw new Error(`Docusaurus error: Duplicate values "${t.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`)}(e),e}),[t,r])}function p(e){let{value:t,tabValues:r}=e;return r.some((e=>e.value===t))}function f(e){let{queryString:t=!1,groupId:r}=e;const s=(0,a.W6)(),l=function(e){let{queryString:t=!1,groupId:r}=e;if("string"==typeof t)return t;if(!1===t)return null;if(!0===t&&!r)throw new Error('Docusaurus error: The <Tabs> component groupId prop is required if queryString=true, because this value is used as the search param name. You can also provide an explicit value such as queryString="my-search-param".');return r??null}({queryString:t,groupId:r});return[(0,i.aZ)(l),(0,n.useCallback)((e=>{if(!l)return;const t=new URLSearchParams(s.location.search);t.set(l,e),s.replace({...s.location,search:t.toString()})}),[l,s])]}function m(e){const{defaultValue:t,queryString:r=!1,groupId:s}=e,l=h(e),[a,i]=(0,n.useState)((()=>function(e){let{defaultValue:t,tabValues:r}=e;if(0===r.length)throw new Error("Docusaurus error: the <Tabs> component requires at least one <TabItem> children component");if(t){if(!p({value:t,tabValues:r}))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${t}" but none of its children has the corresponding value. Available values are: ${r.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);return t}const n=r.find((e=>e.default))??r[0];if(!n)throw new Error("Unexpected error: 0 tabValues");return n.value}({defaultValue:t,tabValues:l}))),[o,d]=f({queryString:r,groupId:s}),[m,b]=function(e){let{groupId:t}=e;const r=function(e){return e?`docusaurus.tab.${e}`:null}(t),[s,l]=(0,u.Dv)(r);return[s,(0,n.useCallback)((e=>{r&&l.set(e)}),[r,l])]}({groupId:s}),x=(()=>{const e=o??m;return p({value:e,tabValues:l})?e:null})();(0,c.A)((()=>{x&&i(x)}),[x]);return{selectedValue:a,selectValue:(0,n.useCallback)((e=>{if(!p({value:e,tabValues:l}))throw new Error(`Can't select invalid tab value=${e}`);i(e),d(e),b(e)}),[d,b,l]),tabValues:l}}var b=r(2303);const x={tabList:"tabList__CuJ",tabItem:"tabItem_LNqP"};var v=r(4848);function j(e){let{className:t,block:r,selectedValue:n,selectValue:a,tabValues:c}=e;const i=[],{blockElementScrollPositionUntilNextRender:o}=(0,l.a_)(),u=e=>{const t=e.currentTarget,r=i.indexOf(t),s=c[r].value;s!==n&&(o(t),a(s))},d=e=>{let t=null;switch(e.key){case"Enter":u(e);break;case"ArrowRight":{const r=i.indexOf(e.currentTarget)+1;t=i[r]??i[0];break}case"ArrowLeft":{const r=i.indexOf(e.currentTarget)-1;t=i[r]??i[i.length-1];break}}t?.focus()};return(0,v.jsx)("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,s.A)("tabs",{"tabs--block":r},t),children:c.map((e=>{let{value:t,label:r,attributes:l}=e;return(0,v.jsx)("li",{role:"tab",tabIndex:n===t?0:-1,"aria-selected":n===t,ref:e=>i.push(e),onKeyDown:d,onClick:u,...l,className:(0,s.A)("tabs__item",x.tabItem,l?.className,{"tabs__item--active":n===t}),children:r??t},t)}))})}function g(e){let{lazy:t,children:r,selectedValue:s}=e;const l=(Array.isArray(r)?r:[r]).filter(Boolean);if(t){const e=l.find((e=>e.props.value===s));return e?(0,n.cloneElement)(e,{className:"margin-top--md"}):null}return(0,v.jsx)("div",{className:"margin-top--md",children:l.map(((e,t)=>(0,n.cloneElement)(e,{key:t,hidden:e.props.value!==s})))})}function y(e){const t=m(e);return(0,v.jsxs)("div",{className:(0,s.A)("tabs-container",x.tabList),children:[(0,v.jsx)(j,{...e,...t}),(0,v.jsx)(g,{...e,...t})]})}function k(e){const t=(0,b.A)();return(0,v.jsx)(y,{...e,children:d(e.children)},String(t))}}}]);