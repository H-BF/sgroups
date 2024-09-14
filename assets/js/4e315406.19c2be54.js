"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[6235],{1811:(e,r,n)=>{n.r(r),n.d(r,{assets:()=>d,contentTitle:()=>a,default:()=>p,frontMatter:()=>i,metadata:()=>o,toc:()=>u});var t=n(4848),s=n(8453),l=n(7861),c=n(26);const i={id:"tls-configuration-server"},a="\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430",o={id:"tech-docs/sgroups/tls-configuration-server",title:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430",description:"\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 TLS (Transport Layer Security) \u043d\u0430 hbf-\u0441\u0435\u0440\u0432\u0435\u0440\u0435 \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u0435\u0442 \u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u043c\u0435\u0436\u0434\u0443 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u043c \u0438 \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u043c,",source:"@site/versioned_docs/version-v2.0.0/tech-docs/sgroups/tls-configuration-server.mdx",sourceDirName:"tech-docs/sgroups",slug:"/tech-docs/sgroups/tls-configuration-server",permalink:"/tech-docs/sgroups/tls-configuration-server",draft:!1,unlisted:!1,tags:[],version:"v2.0.0",frontMatter:{id:"tls-configuration-server"},sidebar:"techDocs",previous:{title:"\u041c\u043e\u043d\u0438\u0442\u043e\u0440\u0438\u043d\u0433",permalink:"/tech-docs/sgroups/monitoring"},next:{title:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u0431\u0430\u0437\u044b \u0434\u0430\u043d\u043d\u044b\u0445",permalink:"/tech-docs/sgroups/database"}},d={},u=[{value:"\u0428\u0430\u0433\u0438 \u043f\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 TLS",id:"\u0448\u0430\u0433\u0438-\u043f\u043e-\u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435-tls",level:2}];function h(e){const r={code:"code",h1:"h1",h2:"h2",p:"p",pre:"pre",...(0,s.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(r.h1,{id:"\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430",children:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430"}),"\n",(0,t.jsx)("div",{children:(0,t.jsx)(r.p,{children:"\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 TLS (Transport Layer Security) \u043d\u0430 hbf-\u0441\u0435\u0440\u0432\u0435\u0440\u0435 \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u0435\u0442 \u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u043c\u0435\u0436\u0434\u0443 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u043c \u0438 \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u043c,\n\u0447\u0442\u043e \u043f\u043e\u0432\u044b\u0448\u0430\u0435\u0442 \u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u044c \u043f\u0435\u0440\u0435\u0434\u0430\u0432\u0430\u0435\u043c\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445. \u0412 \u044d\u0442\u043e\u0439 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u0438 \u043e\u043f\u0438\u0441\u0430\u043d \u043f\u0440\u043e\u0446\u0435\u0441\u0441 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 TLS \u043d\u0430 hbf-\u0441\u0435\u0440\u0432\u0435\u0440\u0435, \u0432\u043a\u043b\u044e\u0447\u0430\u044f\n\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u0435 \u043f\u0440\u0435\u0434\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u043e\u043d\u043d\u043e\u0433\u043e \u0444\u0430\u0439\u043b\u0430."})}),"\n",(0,t.jsxs)("div",{children:[(0,t.jsx)(r.p,{children:"\u041f\u0440\u0435\u0436\u0434\u0435 \u0447\u0435\u043c \u043f\u0440\u0438\u0441\u0442\u0443\u043f\u0438\u0442\u044c \u043a \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 TLS, \u0443\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0443 \u0432\u0430\u0441 \u0435\u0441\u0442\u044c:"}),(0,t.jsxs)("ul",{children:[(0,t.jsx)("li",{children:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u044b\u0439 hbf-\u0441\u0435\u0440\u0432\u0435\u0440"}),(0,t.jsx)("li",{children:"\u0421\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 SSL \u0438 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0439 \u043f\u0440\u0438\u0432\u0430\u0442\u043d\u044b\u0439 \u043a\u043b\u044e\u0447. \u0415\u0441\u043b\u0438 \u0443 \u0432\u0430\u0441 \u0438\u0445 \u043d\u0435\u0442, \u0432\u044b \u043c\u043e\u0436\u0435\u0442\u0435 \u043f\u043e\u043b\u0443\u0447\u0438\u0442\u044c \u0438\u0445 \u0443 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u043e\u043d\u043d\u043e\u0433\u043e\n\u0446\u0435\u043d\u0442\u0440\u0430 (CA) \u0438\u043b\u0438 \u0441\u043e\u0437\u0434\u0430\u0442\u044c \u0441\u0430\u043c\u043e\u043f\u043e\u0434\u043f\u0438\u0441\u0430\u043d\u043d\u044b\u0439 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u0434\u043b\u044f \u0442\u0435\u0441\u0442\u043e\u0432\u044b\u0445 \u0446\u0435\u043b\u0435\u0439."})]})]}),"\n",(0,t.jsx)(r.h2,{id:"\u0448\u0430\u0433\u0438-\u043f\u043e-\u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435-tls",children:"\u0428\u0430\u0433\u0438 \u043f\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 TLS"}),"\n",(0,t.jsxs)("div",{children:[(0,t.jsx)(r.p,{children:"\u0421\u043e\u0437\u0434\u0430\u0439\u0442\u0435 \u0444\u0430\u0439\u043b \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 hbf-\u0441\u0435\u0440\u0432\u0435\u0440\u0430 \u0434\u043b\u044f \u0440\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u044f:"}),(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",children:"sudo nano /etc/cmd/to-nft/internal/tls-config.yaml\n"})}),(0,t.jsx)(r.p,{children:"\u0414\u0430\u043b\u0435\u0435 \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0438\u0442\u044c \u0441\u0435\u043a\u0446\u0438\u044e \u0434\u043b\u044f TLS:"})]}),"\n",(0,t.jsxs)(l.A,{defaltValue:"itls",values:[{label:"Insecure TLS",value:"itls"},{label:"Secure TLS",value:"tls"},{label:"mTLS",value:"mtls"}],children:[(0,t.jsxs)(c.A,{value:"itls",children:[(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",children:'authn:\n  type: tls\n  tls:\n    key-file: "/etc/ssl/private/key-file.pem"\n    cert-file: "/etc/ssl/certs/cert-file.pem"\n    client:\n      verify: skip\n'})}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"type"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,t.jsx)(r.code,{children:"none"})," \u0438\u043b\u0438 ",(0,t.jsx)(r.code,{children:"tls"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"none"})," tls \u043e\u0442\u043a\u043b\u044e\u0447\u0435\u043d, \u043f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"tls"})," tls \u0432\u043a\u043b\u044e\u0447\u0435\u043d."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"key-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"/etc/ssl/private/key-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"./../key-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u043a\u043b\u044e\u0447\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"cert-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"/etc/ssl/certs/cert-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"./../cert-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"verify"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,t.jsx)(r.code,{children:"skip"}),", ",(0,t.jsx)(r.code,{children:"cert-required"})," \u0438\u043b\u0438 ",(0,t.jsx)(r.code,{children:"verify"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"skip"})," \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u0442\u0441\u044f."]})]}),(0,t.jsxs)(c.A,{value:"tls",children:[(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",children:'authn:\n  type: tls\n  tls:\n    key-file: "/etc/ssl/private/key-file.pem"\n    cert-file: "/etc/ssl/certs/cert-file.pem"\n    client:\n      verify: cert-required\n'})}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"type"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,t.jsx)(r.code,{children:"none"})," \u0438\u043b\u0438 ",(0,t.jsx)(r.code,{children:"tls"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"none"})," tls \u043e\u0442\u043a\u043b\u044e\u0447\u0435\u043d, \u043f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"tls"})," tls \u0432\u043a\u043b\u044e\u0447\u0435\u043d."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"key-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"/etc/ssl/private/key-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"./../key-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u043a\u043b\u044e\u0447\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"cert-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"/etc/ssl/certs/cert-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"./../cert-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"verify"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,t.jsx)(r.code,{children:"skip"}),", ",(0,t.jsx)(r.code,{children:"cert-required"})," \u0438\u043b\u0438 ",(0,t.jsx)(r.code,{children:"verify"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"cert-required"})," \u043e\u0442 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043d\u0430\u043b\u0438\u0447\u0438\u0435 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0432, \u043d\u043e \u0441\u043e \u0441\u0442\u043e\u0440\u043e\u043d\u044b \u0441\u0435\u0440\u0432\u0435\u043d\u0430 \u0434\u0430\u043d\u043d\u044b\u0435 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u044b \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u044e\u0442\u0441\u044f."]})]}),(0,t.jsxs)(c.A,{value:"mtls",children:[(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",children:'authn:\n  type: tls\n  tls:\n    key-file: "/etc/ssl/private/key-file.pem"\n    cert-file: "/etc/ssl/certs/cert-file.pem"\n    client:\n      verify: verify\n      ca-files: ["file1.pem", "file2.pem", ...]\n'})}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"type"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,t.jsx)(r.code,{children:"none"})," \u0438\u043b\u0438 ",(0,t.jsx)(r.code,{children:"tls"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"none"})," tls \u043e\u0442\u043a\u043b\u044e\u0447\u0435\u043d, \u043f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0438 ",(0,t.jsx)(r.code,{children:"tls"})," tls \u0432\u043a\u043b\u044e\u0447\u0435\u043d."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"key-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"/etc/ssl/private/key-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"./../key-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u043a\u043b\u044e\u0447\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"cert-file"})," - \u041d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043f\u043e\u043b\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"/etc/ssl/certs/cert-file.pem"}),"  \u0438\u043b\u0438 \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u044b\u0439 \u043f\u0443\u0442\u044c ",(0,t.jsx)(r.code,{children:"./../cert-file.pem"})," \u0441 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435\u043c \u0444\u0430\u0439\u043b\u0430 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"verify"})," - \u0414\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438: ",(0,t.jsx)(r.code,{children:"skip"}),", ",(0,t.jsx)(r.code,{children:"cert-required"})," \u0438\u043b\u0438 ",(0,t.jsx)(r.code,{children:"verify"}),". \u041f\u0440\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438 ",(0,t.jsx)(r.code,{children:"verify"})," \u0432\u043a\u043b\u044e\u0447\u0430\u0435\u0442\u0441\u044f \u0440\u0435\u0436\u0438\u043c mTLS, \u043a\u043e\u0433\u0434\u0430 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c \u0438 \u043f\u0440\u043e\u0438\u0441\u0445\u043e\u0434\u0438\u0442 \u0435\u0433\u043e \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430."]}),(0,t.jsxs)("p",{children:[(0,t.jsx)(r.code,{children:"ca-files"})," - \u041f\u0440\u0438 \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u043d\u043e\u043c \u0440\u0435\u0436\u0438\u043c\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0430 ",(0,t.jsx)(r.code,{children:"verify: verify"})," \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a certificates authorities \u0441 \u0443\u043a\u0430\u0437\u0430\u043d\u0438\u0435\u043c \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0433\u043e \u0438\u043b\u0438 \u043f\u043e\u043b\u043d\u043e\u0433\u043e \u043f\u0443\u0442\u0438 \u043a \u0444\u0430\u0439\u043b\u0430\u043c."]})]})]})]})}function p(e={}){const{wrapper:r}={...(0,s.R)(),...e.components};return r?(0,t.jsx)(r,{...e,children:(0,t.jsx)(h,{...e})}):h(e)}},26:(e,r,n)=>{n.d(r,{A:()=>c});n(6540);var t=n(4164);const s={tabItem:"tabItem_Ymn6"};var l=n(4848);function c(e){let{children:r,hidden:n,className:c}=e;return(0,l.jsx)("div",{role:"tabpanel",className:(0,t.A)(s.tabItem,c),hidden:n,children:r})}},7861:(e,r,n)=>{n.d(r,{A:()=>k});var t=n(6540),s=n(4164),l=n(3104),c=n(6347),i=n(205),a=n(7485),o=n(1682),d=n(9466);function u(e){return t.Children.toArray(e).filter((e=>"\n"!==e)).map((e=>{if(!e||(0,t.isValidElement)(e)&&function(e){const{props:r}=e;return!!r&&"object"==typeof r&&"value"in r}(e))return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)}))?.filter(Boolean)??[]}function h(e){const{values:r,children:n}=e;return(0,t.useMemo)((()=>{const e=r??function(e){return u(e).map((e=>{let{props:{value:r,label:n,attributes:t,default:s}}=e;return{value:r,label:n,attributes:t,default:s}}))}(n);return function(e){const r=(0,o.X)(e,((e,r)=>e.value===r.value));if(r.length>0)throw new Error(`Docusaurus error: Duplicate values "${r.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`)}(e),e}),[r,n])}function p(e){let{value:r,tabValues:n}=e;return n.some((e=>e.value===r))}function f(e){let{queryString:r=!1,groupId:n}=e;const s=(0,c.W6)(),l=function(e){let{queryString:r=!1,groupId:n}=e;if("string"==typeof r)return r;if(!1===r)return null;if(!0===r&&!n)throw new Error('Docusaurus error: The <Tabs> component groupId prop is required if queryString=true, because this value is used as the search param name. You can also provide an explicit value such as queryString="my-search-param".');return n??null}({queryString:r,groupId:n});return[(0,a.aZ)(l),(0,t.useCallback)((e=>{if(!l)return;const r=new URLSearchParams(s.location.search);r.set(l,e),s.replace({...s.location,search:r.toString()})}),[l,s])]}function x(e){const{defaultValue:r,queryString:n=!1,groupId:s}=e,l=h(e),[c,a]=(0,t.useState)((()=>function(e){let{defaultValue:r,tabValues:n}=e;if(0===n.length)throw new Error("Docusaurus error: the <Tabs> component requires at least one <TabItem> children component");if(r){if(!p({value:r,tabValues:n}))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${r}" but none of its children has the corresponding value. Available values are: ${n.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);return r}const t=n.find((e=>e.default))??n[0];if(!t)throw new Error("Unexpected error: 0 tabValues");return t.value}({defaultValue:r,tabValues:l}))),[o,u]=f({queryString:n,groupId:s}),[x,j]=function(e){let{groupId:r}=e;const n=function(e){return e?`docusaurus.tab.${e}`:null}(r),[s,l]=(0,d.Dv)(n);return[s,(0,t.useCallback)((e=>{n&&l.set(e)}),[n,l])]}({groupId:s}),m=(()=>{const e=o??x;return p({value:e,tabValues:l})?e:null})();(0,i.A)((()=>{m&&a(m)}),[m]);return{selectedValue:c,selectValue:(0,t.useCallback)((e=>{if(!p({value:e,tabValues:l}))throw new Error(`Can't select invalid tab value=${e}`);a(e),u(e),j(e)}),[u,j,l]),tabValues:l}}var j=n(2303);const m={tabList:"tabList__CuJ",tabItem:"tabItem_LNqP"};var v=n(4848);function b(e){let{className:r,block:n,selectedValue:t,selectValue:c,tabValues:i}=e;const a=[],{blockElementScrollPositionUntilNextRender:o}=(0,l.a_)(),d=e=>{const r=e.currentTarget,n=a.indexOf(r),s=i[n].value;s!==t&&(o(r),c(s))},u=e=>{let r=null;switch(e.key){case"Enter":d(e);break;case"ArrowRight":{const n=a.indexOf(e.currentTarget)+1;r=a[n]??a[0];break}case"ArrowLeft":{const n=a.indexOf(e.currentTarget)-1;r=a[n]??a[a.length-1];break}}r?.focus()};return(0,v.jsx)("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,s.A)("tabs",{"tabs--block":n},r),children:i.map((e=>{let{value:r,label:n,attributes:l}=e;return(0,v.jsx)("li",{role:"tab",tabIndex:t===r?0:-1,"aria-selected":t===r,ref:e=>a.push(e),onKeyDown:u,onClick:d,...l,className:(0,s.A)("tabs__item",m.tabItem,l?.className,{"tabs__item--active":t===r}),children:n??r},r)}))})}function y(e){let{lazy:r,children:n,selectedValue:s}=e;const l=(Array.isArray(n)?n:[n]).filter(Boolean);if(r){const e=l.find((e=>e.props.value===s));return e?(0,t.cloneElement)(e,{className:"margin-top--md"}):null}return(0,v.jsx)("div",{className:"margin-top--md",children:l.map(((e,r)=>(0,t.cloneElement)(e,{key:r,hidden:e.props.value!==s})))})}function g(e){const r=x(e);return(0,v.jsxs)("div",{className:(0,s.A)("tabs-container",m.tabList),children:[(0,v.jsx)(b,{...e,...r}),(0,v.jsx)(y,{...e,...r})]})}function k(e){const r=(0,j.A)();return(0,v.jsx)(g,{...e,children:u(e.children)},String(r))}},8453:(e,r,n)=>{n.d(r,{R:()=>c,x:()=>i});var t=n(6540);const s={},l=t.createContext(s);function c(e){const r=t.useContext(l);return t.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function i(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(s):e.components||s:c(e.components),t.createElement(l.Provider,{value:r},e.children)}}}]);