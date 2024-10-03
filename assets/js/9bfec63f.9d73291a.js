"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9429],{6779:(n,e,l)=>{l.r(e),l.d(e,{assets:()=>d,contentTitle:()=>t,default:()=>h,frontMatter:()=>r,metadata:()=>c,toc:()=>o});var i=l(4848),s=l(8453);const r={id:"toolset"},t="\u0412\u044b\u0431\u043e\u0440 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0430",c={id:"info/toolset",title:"\u0412\u044b\u0431\u043e\u0440 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0430",description:"\u0418\u0437\u043d\u0430\u0447\u0430\u043b\u044c\u043d\u043e \u0431\u044b\u043b\u043e \u043f\u0440\u0438\u043d\u044f\u0442\u043e \u0440\u0435\u0448\u0435\u043d\u0438\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u044c \u0442\u0435\u0445\u043d\u043e\u043b\u043e\u0433\u0438\u044e ebpf, \u0442\u0430\u043a \u043a\u0430\u043a \u043e\u043d\u0430 \u043e\u0431\u043b\u0430\u0434\u0430\u0435\u0442 \u0440\u044f\u0434\u043e\u043c \u043e\u0447\u0435\u0432\u0438\u0434\u043d\u044b\u0445 \u043f\u0440\u0435\u0438\u043c\u0443\u0449\u0435\u0441\u0442\u0432 \u043f\u043e",source:"@site/versioned_docs/version-v2.0.0/info/toolset.mdx",sourceDirName:"info",slug:"/info/toolset",permalink:"/info/toolset",draft:!1,unlisted:!1,tags:[],version:"v2.0.0",frontMatter:{id:"toolset"},sidebar:"informationSidebar",previous:{title:"\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 SGroups",permalink:"/info/introduction"},next:{title:"\u0422\u0435\u0440\u043c\u0438\u043d\u043e\u043b\u043e\u0433\u0438\u044f",permalink:"/info/terminology"}},d={},o=[{value:"iptables",id:"iptables",level:2},{value:"ebpf",id:"ebpf",level:2},{value:"nftables",id:"nftables",level:2}];function a(n){const e={h1:"h1",h2:"h2",li:"li",p:"p",ul:"ul",...(0,s.R)(),...n.components},{Details:l}=e;return l||function(n,e){throw new Error("Expected "+(e?"component":"object")+" `"+n+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(e.h1,{id:"\u0432\u044b\u0431\u043e\u0440-\u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0430",children:"\u0412\u044b\u0431\u043e\u0440 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0430"}),"\n",(0,i.jsx)("span",{className:"paragraph",children:(0,i.jsx)(e.p,{children:"\u0418\u0437\u043d\u0430\u0447\u0430\u043b\u044c\u043d\u043e \u0431\u044b\u043b\u043e \u043f\u0440\u0438\u043d\u044f\u0442\u043e \u0440\u0435\u0448\u0435\u043d\u0438\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u044c \u0442\u0435\u0445\u043d\u043e\u043b\u043e\u0433\u0438\u044e ebpf, \u0442\u0430\u043a \u043a\u0430\u043a \u043e\u043d\u0430 \u043e\u0431\u043b\u0430\u0434\u0430\u0435\u0442 \u0440\u044f\u0434\u043e\u043c \u043e\u0447\u0435\u0432\u0438\u0434\u043d\u044b\u0445 \u043f\u0440\u0435\u0438\u043c\u0443\u0449\u0435\u0441\u0442\u0432 \u043f\u043e\n\u0441\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u044e \u0441 nftables \u0438 iptables. \u041e\u0434\u043d\u0430\u043a\u043e, \u0443\u0447\u0438\u0442\u044b\u0432\u0430\u044f \u0442\u043e\u0442 \u0444\u0430\u043a\u0442, \u0447\u0442\u043e \u043c\u043d\u043e\u0433\u0438\u0435 \u043a\u0440\u0443\u043f\u043d\u044b\u0435 \u043a\u043e\u043c\u043f\u0430\u043d\u0438\u0438 \u0434\u043e \u0441\u0438\u0445 \u043f\u043e\u0440 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u044e\u0442\n\u0443\u0441\u0442\u0430\u0440\u0435\u0432\u0448\u0438\u0435 \u0432\u0435\u0440\u0441\u0438\u0438 \u044f\u0434\u0440\u0430 Linux, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u043d\u0435 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u044e\u0442 ebpf, \u043c\u044b \u0431\u044b\u043b\u0438 \u0432\u044b\u043d\u0443\u0436\u0434\u0435\u043d\u044b \u043f\u0435\u0440\u0435\u0441\u043c\u043e\u0442\u0440\u0435\u0442\u044c \u0441\u0432\u043e\u0435 \u0440\u0435\u0448\u0435\u043d\u0438\u0435 \u0432 \u043f\u043e\u043b\u044c\u0437\u0443\nnftables (\u043f\u0440\u0435\u0438\u043c\u0443\u0449\u0435\u0441\u0442\u0432\u0430 \u043e\u043f\u0438\u0441\u0430\u043d\u044b \u043d\u0438\u0436\u0435)."})}),"\n",(0,i.jsx)("span",{className:"paragraph",children:(0,i.jsx)(e.p,{children:"\u041d\u0430\u0448\u0430 \u043a\u043e\u043c\u0430\u043d\u0434\u0430 \u0432\u0441\u0435\u0433\u0434\u0430 \u0443\u0447\u0438\u0442\u044b\u0432\u0430\u0435\u0442 \u043f\u043e\u0442\u0440\u0435\u0431\u043d\u043e\u0441\u0442\u0438 \u043d\u0430\u0448\u0438\u0445 \u043a\u043b\u0438\u0435\u043d\u0442\u043e\u0432 \u0438 \u0440\u0430\u0437\u0440\u0430\u0431\u0430\u0442\u044b\u0432\u0430\u0435\u0442 \u0430\u0440\u0445\u0438\u0442\u0435\u043a\u0442\u0443\u0440\u0443 \u0441 \u0443\u0447\u0435\u0442\u043e\u043c \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u0438\n\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f SGroups \u043d\u0430 ebpf. \u041c\u044b \u0443\u0432\u0435\u0440\u0435\u043d\u044b, \u0447\u0442\u043e \u0432 \u0431\u0443\u0434\u0443\u0449\u0435\u043c \u044d\u0442\u043e \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0442 \u043d\u0430\u0438\u0431\u043e\u043b\u044c\u0448\u0443\u044e \u044d\u0444\u0444\u0435\u043a\u0442\u0438\u0432\u043d\u043e\u0441\u0442\u044c \u0438 \u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u044c \u0440\u0430\u0431\u043e\u0442\u044b\n\u043d\u0430\u0448\u0435\u0439 \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u0434\u043b\u044f \u0432\u0441\u0435\u0445 \u043d\u0430\u0448\u0438\u0445 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439."})}),"\n",(0,i.jsx)(e.h2,{id:"iptables",children:"iptables"}),"\n",(0,i.jsxs)(l,{children:[(0,i.jsx)("summary",{children:"\u041f\u043b\u044e\u0441\u044b"}),(0,i.jsxs)(e.ul,{children:["\n",(0,i.jsx)(e.li,{children:"\u0418\u043c\u0435\u0435\u0442 \u0434\u043b\u0438\u0442\u0435\u043b\u044c\u043d\u0443\u044e \u0438\u0441\u0442\u043e\u0440\u0438\u044e \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f \u0438 \u0448\u0438\u0440\u043e\u043a\u043e\u0435 \u0440\u0430\u0441\u043f\u0440\u043e\u0441\u0442\u0440\u0430\u043d\u0435\u043d\u0438\u0435."}),"\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u043b\u0430\u0434\u0430\u0435\u0442 \u043a\u0430\u0447\u0435\u0441\u0442\u0432\u0435\u043d\u043d\u043e\u0439 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u0435\u0439 \u0438 \u043e\u0431\u0448\u0438\u0440\u043d\u044b\u043c \u043d\u0430\u0431\u043e\u0440\u043e\u043c \u0440\u0435\u0441\u0443\u0440\u0441\u043e\u0432 \u0434\u043b\u044f \u043e\u0431\u0443\u0447\u0435\u043d\u0438\u044f \u0438 \u043e\u0442\u043b\u0430\u0434\u043a\u0438."}),"\n",(0,i.jsx)(e.li,{children:"\u041f\u0440\u0435\u0434\u0441\u0442\u0430\u0432\u043b\u044f\u0435\u0442 \u0441\u043e\u0431\u043e\u0439 \u043c\u043e\u0449\u043d\u044b\u0439 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442 \u0434\u043b\u044f \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u044f \u0442\u0440\u0430\u0444\u0438\u043a\u043e\u043c \u0441 \u043e\u0431\u0448\u0438\u0440\u043d\u044b\u043c \u043d\u0430\u0431\u043e\u0440\u043e\u043c \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a \u0438 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u0435\u0439."}),"\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u0435\u0442\u0441\u044f \u0445\u043e\u0440\u043e\u0448\u0435\u0439 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u043a\u043e\u0439 \u0438 \u0438\u043c\u0435\u0435\u0442 \u0448\u0438\u0440\u043e\u043a\u043e\u0435 \u0441\u043e\u043e\u0431\u0449\u0435\u0441\u0442\u0432\u043e \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439."}),"\n",(0,i.jsx)(e.li,{children:"\u0421\u043e\u0432\u043c\u0435\u0441\u0442\u0438\u043c \u0441 \u0434\u0440\u0443\u0433\u0438\u043c\u0438 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0430\u043c\u0438, \u0442\u0430\u043a\u0438\u043c\u0438 \u043a\u0430\u043a fail2ban, \u0434\u043b\u044f \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0435\u043d\u0438\u044f \u0434\u043e\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0439 \u0437\u0430\u0449\u0438\u0442\u044b \u0441\u0435\u0440\u0432\u0435\u0440\u0430."}),"\n"]})]}),"\n",(0,i.jsxs)(l,{className:"alert alert--danger",children:[(0,i.jsx)("summary",{children:"\u041c\u0438\u043d\u0443\u0441\u044b"}),(0,i.jsxs)(e.ul,{children:["\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u043b\u0430\u0434\u0430\u0435\u0442 \u0441\u043b\u043e\u0436\u043d\u044b\u043c \u0438 \u0437\u0430\u043f\u0443\u0442\u0430\u043d\u043d\u044b\u043c \u0441\u0438\u043d\u0442\u0430\u043a\u0441\u0438\u0441\u043e\u043c, \u0447\u0442\u043e \u043c\u043e\u0436\u0435\u0442 \u0437\u0430\u0442\u0440\u0443\u0434\u043d\u0438\u0442\u044c \u0440\u0430\u0431\u043e\u0442\u0443 \u043d\u0430\u0447\u0438\u043d\u0430\u044e\u0449\u0438\u0445 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439."}),"\n",(0,i.jsx)(e.li,{children:"\u041d\u0435 \u043f\u043e\u043b\u043d\u043e\u0441\u0442\u044c\u044e \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442 \u0434\u0435\u043a\u043b\u0430\u0440\u0430\u0442\u0438\u0432\u043d\u0443\u044e \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044e, \u0447\u0442\u043e \u0443\u0441\u043b\u043e\u0436\u043d\u044f\u0435\u0442 \u043e\u0442\u0441\u043b\u0435\u0436\u0438\u0432\u0430\u043d\u0438\u0435 \u0438 \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u0430\u043c\u0438."}),"\n",(0,i.jsx)(e.li,{children:"\u041d\u0435\u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0444\u0443\u043d\u043a\u0446\u0438\u0438, \u0442\u0430\u043a\u0438\u0435 \u043a\u0430\u043a \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0430 \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432, \u043c\u043e\u0433\u0443\u0442 \u0440\u0430\u0431\u043e\u0442\u0430\u0442\u044c \u043c\u0435\u0434\u043b\u0435\u043d\u043d\u0435\u0435, \u0447\u0435\u043c \u0432 nftables \u0438 ebpf."}),"\n",(0,i.jsx)(e.li,{children:"\u0418\u043c\u0435\u0435\u0442 \u043e\u0433\u0440\u0430\u043d\u0438\u0447\u0435\u043d\u043d\u0443\u044e \u0433\u0438\u0431\u043a\u043e\u0441\u0442\u044c \u043f\u043e \u0441\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u044e \u0441 \u0431\u043e\u043b\u0435\u0435 \u0441\u043e\u0432\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u043c\u0438 \u0440\u0435\u0448\u0435\u043d\u0438\u044f\u043c\u0438, \u0442\u0430\u043a\u0438\u043c\u0438 \u043a\u0430\u043a nftables \u0438 ebpf."}),"\n"]})]}),"\n",(0,i.jsx)(e.h2,{id:"ebpf",children:"ebpf"}),"\n",(0,i.jsxs)(l,{children:[(0,i.jsx)("summary",{children:"\u041f\u043b\u044e\u0441\u044b"}),(0,i.jsxs)(e.ul,{children:["\n",(0,i.jsx)(e.li,{children:"\u0412\u044b\u0441\u043e\u043a\u0430\u044f \u043f\u0440\u043e\u0438\u0437\u0432\u043e\u0434\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u044c \u0438 \u0433\u0438\u0431\u043a\u043e\u0441\u0442\u044c \u0434\u043e\u0441\u0442\u0438\u0433\u0430\u044e\u0442\u0441\u044f \u0437\u0430 \u0441\u0447\u0435\u0442 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f JIT-\u043a\u043e\u043c\u043f\u0438\u043b\u044f\u0446\u0438\u0438 \u0438 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u0438 \u0434\u0438\u043d\u0430\u043c\u0438\u0447\u0435\u0441\u043a\u043e\u0439 \u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0438 \u0438 \u043e\u0442\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c. \u042d\u0442\u043e \u043e\u0441\u043e\u0431\u0435\u043d\u043d\u043e \u0432\u0430\u0436\u043d\u043e \u0432 \u0443\u0441\u043b\u043e\u0432\u0438\u044f\u0445 \u0432\u044b\u0441\u043e\u043a\u043e\u0439 \u043d\u0430\u0433\u0440\u0443\u0437\u043a\u0438 \u0438 \u0441\u043b\u043e\u0436\u043d\u043e\u0439 \u0441\u0435\u0442\u0435\u0432\u043e\u0439 \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b."}),"\n",(0,i.jsx)(e.li,{children:"\u0411\u043e\u043b\u0435\u0435 \u0448\u0438\u0440\u043e\u043a\u0438\u0439 \u043d\u0430\u0431\u043e\u0440 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u043e\u0432 \u0434\u043b\u044f \u0430\u043d\u0430\u043b\u0438\u0437\u0430 \u0441\u0435\u0442\u0435\u0432\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0438 \u043f\u0440\u0438\u043d\u044f\u0442\u0438\u044f \u0440\u0435\u0448\u0435\u043d\u0438\u0439 \u043d\u0430 \u043e\u0441\u043d\u043e\u0432\u0435 \u0440\u0430\u0437\u043b\u0438\u0447\u043d\u044b\u0445 \u043c\u0435\u0442\u0440\u0438\u043a \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u0435\u0442 \u044d\u0444\u0444\u0435\u043a\u0442\u0438\u0432\u043d\u043e \u043a\u043e\u043d\u0442\u0440\u043e\u043b\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0441\u0435\u0442\u0435\u0432\u043e\u0439 \u0442\u0440\u0430\u0444\u0438\u043a."}),"\n",(0,i.jsx)(e.li,{children:"\u0423\u043d\u0438\u0432\u0435\u0440\u0441\u0430\u043b\u044c\u043d\u043e\u0441\u0442\u044c ebpf \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u0435\u0442 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u044c \u044d\u0442\u0443 \u0442\u0435\u0445\u043d\u043e\u043b\u043e\u0433\u0438\u044e \u043d\u0435 \u0442\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0437\u0430\u0434\u0430\u0447 \u0431\u0440\u0430\u043d\u0434\u043c\u0430\u0443\u044d\u0440\u0430, \u043d\u043e \u0438 \u0434\u043b\u044f \u043c\u043e\u043d\u0438\u0442\u043e\u0440\u0438\u043d\u0433\u0430 \u0438 \u0430\u043d\u0430\u043b\u0438\u0437\u0430 \u0441\u0435\u0442\u0435\u0432\u043e\u0433\u043e \u0442\u0440\u0430\u0444\u0438\u043a\u0430."}),"\n"]})]}),"\n",(0,i.jsxs)(l,{className:"alert alert--danger",children:[(0,i.jsx)("summary",{children:"\u041c\u0438\u043d\u0443\u0441\u044b"}),(0,i.jsxs)(e.ul,{children:["\n",(0,i.jsx)(e.li,{children:"\u041e\u0433\u0440\u0430\u043d\u0438\u0447\u0435\u043d\u0438\u044f \u0432 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u044f\u0445: ebpf \u043d\u0435 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442 \u043d\u0435\u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0444\u0443\u043d\u043a\u0446\u0438\u0438, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u043c\u043e\u0433\u0443\u0442 \u0431\u044b\u0442\u044c \u043f\u043e\u043b\u0435\u0437\u043d\u044b \u0432 \u043a\u0430\u0447\u0435\u0441\u0442\u0432\u0435 \u0431\u0440\u0430\u043d\u0434\u043c\u0430\u0443\u044d\u0440\u0430, \u043d\u0430\u043f\u0440\u0438\u043c\u0435\u0440, \u043e\u0442\u0441\u043b\u0435\u0436\u0438\u0432\u0430\u043d\u0438\u0435 \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u044f \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f."}),"\n",(0,i.jsx)(e.li,{children:"\u0421\u043b\u043e\u0436\u043d\u043e\u0441\u0442\u044c \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438: \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u0435 ebpf \u0442\u0440\u0435\u0431\u0443\u0435\u0442 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u0443\u0440\u043e\u0432\u043d\u044f \u0437\u043d\u0430\u043d\u0438\u0439, \u0447\u0442\u043e \u043c\u043e\u0436\u0435\u0442 \u0441\u0434\u0435\u043b\u0430\u0442\u044c \u0435\u0433\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0443 \u0438 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u0435 \u0431\u043e\u043b\u0435\u0435 \u0441\u043b\u043e\u0436\u043d\u044b\u043c \u0434\u043b\u044f \u043d\u0435\u043e\u043f\u044b\u0442\u043d\u044b\u0445 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439. \u0423\u0447\u0438\u0442\u044b\u0432\u0430\u0439\u0442\u0435 \u044d\u0442\u043e \u043f\u0440\u0438 \u0432\u044b\u0431\u043e\u0440\u0435 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0430 \u0434\u043b\u044f \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0435\u043d\u0438\u044f \u0431\u0435\u0437\u043e\u043f\u0430\u0441\u043d\u043e\u0441\u0442\u0438 \u0432\u0430\u0448\u0435\u0439 \u0441\u0435\u0442\u0435\u0432\u043e\u0439 \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b."}),"\n"]})]}),"\n",(0,i.jsx)(e.h2,{id:"nftables",children:"nftables"}),"\n",(0,i.jsxs)(l,{children:[(0,i.jsx)("summary",{children:"\u041f\u043b\u044e\u0441\u044b"}),(0,i.jsxs)(e.ul,{children:["\n",(0,i.jsx)(e.li,{children:"\u0418\u043c\u0435\u0435\u0442 \u043f\u0440\u043e\u0441\u0442\u043e\u0439 \u0438 \u043f\u043e\u043d\u044f\u0442\u043d\u044b\u0439 \u0441\u0438\u043d\u0442\u0430\u043a\u0441\u0438\u0441, \u0447\u0442\u043e \u0443\u043f\u0440\u043e\u0449\u0430\u0435\u0442 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0438 \u043e\u0442\u043b\u0430\u0434\u043a\u0443 \u043f\u0440\u0430\u0432\u0438\u043b."}),"\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u0435\u0442 \u043f\u043e\u043b\u043d\u043e\u0441\u0442\u044c\u044e \u0434\u0435\u043a\u043b\u0430\u0440\u0430\u0442\u0438\u0432\u043d\u044b\u0439 \u043f\u043e\u0434\u0445\u043e\u0434 \u043a \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 \u0431\u0440\u0430\u043d\u0434\u043c\u0430\u0443\u044d\u0440\u0430."}),"\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u0440\u0430\u0431\u0430\u0442\u044b\u0432\u0430\u0435\u0442 \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u044b \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0431\u044b\u0441\u0442\u0440\u0435\u0435, \u0447\u0435\u043c iptables."}),"\n",(0,i.jsx)(e.li,{children:"\u041f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442 \u0448\u0438\u0440\u043e\u043a\u0438\u0439 \u0441\u043f\u0435\u043a\u0442\u0440 \u0444\u0443\u043d\u043a\u0446\u0438\u0439, \u0432\u043a\u043b\u044e\u0447\u0430\u044f \u043e\u0442\u043b\u043e\u0436\u0435\u043d\u043d\u043e\u0435 \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u043f\u0440\u0430\u0432\u0438\u043b \u0438 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u043e\u0435 \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0432\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u043c\u0438 \u043f\u0440\u0430\u0432\u0438\u043b\u0430\u043c\u0438."}),"\n",(0,i.jsx)(e.li,{children:"\u041f\u043e\u0437\u0432\u043e\u043b\u044f\u0435\u0442 \u0434\u0438\u043d\u0430\u043c\u0438\u0447\u0435\u0441\u043a\u0438 \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u0442\u044c \u043f\u0440\u0430\u0432\u0438\u043b\u0430 \u0431\u0435\u0437 \u043f\u0435\u0440\u0435\u0437\u0430\u0433\u0440\u0443\u0437\u043a\u0438 \u0438\u043b\u0438 \u043f\u0435\u0440\u0435\u043a\u043e\u043c\u043f\u0438\u043b\u044f\u0446\u0438\u0438 \u044f\u0434\u0440\u0430, \u0447\u0442\u043e \u043e\u0441\u043e\u0431\u0435\u043d\u043d\u043e \u0432\u0430\u0436\u043d\u043e \u0432 \u0441\u043b\u0443\u0447\u0430\u044f\u0445, \u043a\u043e\u0433\u0434\u0430 \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e \u0431\u044b\u0441\u0442\u0440\u043e \u0438\u0437\u043c\u0435\u043d\u0438\u0442\u044c \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044e \u0431\u0440\u0430\u043d\u0434\u043c\u0430\u0443\u044d\u0440\u0430 \u0432 \u0440\u0435\u0430\u043b\u044c\u043d\u043e\u043c \u0432\u0440\u0435\u043c\u0435\u043d\u0438."}),"\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u043b\u0430\u0434\u0430\u0435\u0442 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u044c\u044e \u0433\u0440\u0443\u043f\u043f\u0438\u0440\u043e\u0432\u043a\u0438 \u043f\u0440\u0430\u0432\u0438\u043b \u0434\u043b\u044f \u0431\u043e\u043b\u0435\u0435 \u044d\u0444\u0444\u0435\u043a\u0442\u0438\u0432\u043d\u043e\u0433\u043e \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430\u043c\u0438, \u0441\u0432\u044f\u0437\u0430\u043d\u043d\u044b\u043c\u0438 \u0441 \u0440\u0430\u0437\u043b\u0438\u0447\u043d\u044b\u043c\u0438 \u0433\u0440\u0443\u043f\u043f\u0430\u043c\u0438 \u043f\u0430\u043a\u0435\u0442\u043e\u0432."}),"\n",(0,i.jsx)(e.li,{children:"\u041e\u0431\u043b\u0430\u0434\u0430\u0435\u0442 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u043a\u043e\u0439 \u0431\u043e\u043b\u0435\u0435 \u0441\u043b\u043e\u0436\u043d\u044b\u0445 \u0442\u0438\u043f\u043e\u0432 \u043c\u0430\u0442\u0447\u0435\u0439, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u043c\u043e\u0433\u0443\u0442 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u044c\u0441\u044f \u0434\u043b\u044f \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u0438\u044f \u043a\u043e\u043d\u043a\u0440\u0435\u0442\u043d\u044b\u0445 \u0443\u0441\u043b\u043e\u0432\u0438\u0439, \u0442\u0430\u043a\u0438\u0445 \u043a\u0430\u043a \u043d\u0430\u043b\u0438\u0447\u0438\u0435 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u043d\u044b\u0445 \u0444\u043b\u0430\u0433\u043e\u0432 TCP \u0438\u043b\u0438 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0439 IP-\u0430\u0434\u0440\u0435\u0441\u043e\u0432."}),"\n",(0,i.jsx)(e.li,{children:"\u041f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442 \u043d\u0430\u0442\u0438\u0432\u043d\u044b\u0439 \u0441\u0438\u043d\u0442\u0430\u043a\u0441\u0438\u0441 \u0434\u043b\u044f \u0440\u0430\u0431\u043e\u0442\u044b \u0441 IP-\u0430\u0434\u0440\u0435\u0441\u0430\u043c\u0438 \u0438 \u0434\u0440\u0443\u0433\u0438\u043c\u0438 \u0442\u0438\u043f\u0430\u043c\u0438 \u0434\u0430\u043d\u043d\u044b\u0445, \u0447\u0442\u043e \u0443\u043f\u0440\u043e\u0449\u0430\u0435\u0442 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044e \u0431\u0440\u0430\u043d\u0434\u043c\u0430\u0443\u044d\u0440\u0430."}),"\n",(0,i.jsx)(e.li,{children:"\u041f\u043e\u0437\u0432\u043e\u043b\u044f\u0435\u0442 \u043e\u0442\u0441\u043b\u0435\u0436\u0438\u0432\u0430\u0442\u044c \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0439, \u0447\u0442\u043e \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u0435\u0442 \u0441\u043e\u0437\u0434\u0430\u0432\u0430\u0442\u044c \u0431\u043e\u043b\u0435\u0435 \u0441\u043b\u043e\u0436\u043d\u044b\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u0430, \u043e\u0441\u043d\u043e\u0432\u0430\u043d\u043d\u044b\u0435 \u043d\u0430 \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0438 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f."}),"\n"]})]}),"\n",(0,i.jsxs)(l,{className:"alert alert--danger",children:[(0,i.jsx)("summary",{children:"\u041c\u0438\u043d\u0443\u0441\u044b"}),(0,i.jsxs)(e.ul,{children:["\n",(0,i.jsx)(e.li,{children:"\u041e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u043e \u043d\u043e\u0432\u044b\u0439 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u0443 \u043d\u0435\u0433\u043e \u043c\u0435\u043d\u044c\u0448\u0435 \u0441\u043e\u043e\u0431\u0449\u0435\u0441\u0442\u0432\u043e \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439 \u0438 \u0440\u0435\u0441\u0443\u0440\u0441\u043e\u0432 \u0434\u043b\u044f \u043e\u0431\u0443\u0447\u0435\u043d\u0438\u044f \u0438 \u043e\u0442\u043b\u0430\u0434\u043a\u0438, \u0447\u0435\u043c \u0443 iptables."}),"\n",(0,i.jsx)(e.li,{children:"\u041d\u0435\u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0444\u0443\u043d\u043a\u0446\u0438\u0438, \u0442\u0430\u043a\u0438\u0435 \u043a\u0430\u043a \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u043a\u0430 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u043d\u044b\u0445 \u043c\u043e\u0434\u0443\u043b\u0435\u0439 \u044f\u0434\u0440\u0430, \u043c\u043e\u0433\u0443\u0442 \u0431\u044b\u0442\u044c \u043e\u0433\u0440\u0430\u043d\u0438\u0447\u0435\u043d\u044b."}),"\n",(0,i.jsx)(e.li,{children:"\u041d\u0435 \u0432\u0441\u0435 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u0438, \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b\u0435 \u0432 iptables, \u043c\u043e\u0433\u0443\u0442 \u0431\u044b\u0442\u044c \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b \u0432 nftables."}),"\n"]})]})]})}function h(n={}){const{wrapper:e}={...(0,s.R)(),...n.components};return e?(0,i.jsx)(e,{...n,children:(0,i.jsx)(a,{...n})}):a(n)}},8453:(n,e,l)=>{l.d(e,{R:()=>t,x:()=>c});var i=l(6540);const s={},r=i.createContext(s);function t(n){const e=i.useContext(r);return i.useMemo((function(){return"function"==typeof n?n(e):{...e,...n}}),[e,n])}function c(n){let e;return e=n.disableParentContext?"function"==typeof n.components?n.components(s):n.components||s:t(n.components),i.createElement(r.Provider,{value:e},n.children)}}}]);