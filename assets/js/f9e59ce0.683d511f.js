"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[4365],{2096:(e,t,s)=>{s.r(t),s.d(t,{assets:()=>o,contentTitle:()=>l,default:()=>x,frontMatter:()=>i,metadata:()=>a,toc:()=>h});var r=s(4848),n=s(8453),c=s(7861),d=s(26);const i={id:"chains"},l="Chains",a={id:"tech-docs/to-nft/nftables/chains",title:"Chains",description:"\u0412 \u043d\u0430\u0448\u0435\u0439 \u0440\u0435\u0430\u043b\u0438\u0437\u0430\u0446\u0438\u0438 \u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u043c\u044b \u0432\u0432\u043e\u0434\u0438\u043c \u0434\u043b\u044f INPUT \u0438 OUTPUT \u043f\u043e\u043d\u044f\u0442\u0438\u0435 2-\u0445 \u0446\u0435\u043f\u043e\u0447\u0435\u043a. \u041f\u0435\u0440\u0432\u0430\u044f \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0442\u043e\u0447\u043a\u043e\u0439 \u0432\u0445\u043e\u0434\u0430",source:"@site/versioned_docs/version-v1.14.0/tech-docs/to-nft/nftables/chains.mdx",sourceDirName:"tech-docs/to-nft/nftables",slug:"/tech-docs/to-nft/nftables/chains",permalink:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/chains",draft:!1,unlisted:!1,tags:[],version:"v1.14.0",frontMatter:{id:"chains"},sidebar:"techDocs",previous:{title:"IPSet",permalink:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/ipset"},next:{title:"Verdict Statment",permalink:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement"}},o={},h=[{value:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435",id:"\u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435",level:4},{value:"\u041f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",id:"\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",level:4},{value:"\u0428\u0430\u0431\u043b\u043e\u043d",id:"\u0448\u0430\u0431\u043b\u043e\u043d",level:4},{value:"\u041f\u0440\u0438\u043c\u0435\u0440 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f",id:"\u043f\u0440\u0438\u043c\u0435\u0440-\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f",level:4},{value:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435",id:"\u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435-1",level:4},{value:"\u041f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",id:"\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b-1",level:4},{value:"\u0428\u0430\u0431\u043b\u043e\u043d",id:"\u0448\u0430\u0431\u043b\u043e\u043d-1",level:4},{value:"\u041f\u0440\u0438\u043c\u0435\u0440 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f",id:"\u043f\u0440\u0438\u043c\u0435\u0440-\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f-1",level:4}];function u(e){const t={a:"a",code:"code",em:"em",h1:"h1",h4:"h4",p:"p",pre:"pre",...(0,n.R)(),...e.components};return(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(t.h1,{id:"chains",children:"Chains"}),"\n",(0,r.jsx)("div",{className:"paragraph",children:(0,r.jsxs)(t.p,{children:["\u0412 \u043d\u0430\u0448\u0435\u0439 \u0440\u0435\u0430\u043b\u0438\u0437\u0430\u0446\u0438\u0438 \u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u043c\u044b \u0432\u0432\u043e\u0434\u0438\u043c \u0434\u043b\u044f INPUT \u0438 OUTPUT \u043f\u043e\u043d\u044f\u0442\u0438\u0435 2-\u0445 \u0446\u0435\u043f\u043e\u0447\u0435\u043a. ",(0,r.jsx)(t.em,{children:"\u041f\u0435\u0440\u0432\u0430\u044f"})," \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0442\u043e\u0447\u043a\u043e\u0439 \u0432\u0445\u043e\u0434\u0430\n\u0434\u043b\u044f \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0438\u0437 \u0441\u0435\u0442\u0435\u0432\u043e\u0433\u043e \u0441\u0442\u0435\u043a\u0430, \u0432 \u043d\u0435\u0439 \u0443\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u0445\u0443\u043a (input, prerouting, postrouting) \u0438 \u043f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f, \u0442\u0430\u043a \u0436\u0435\n\u044d\u0442\u0430 \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u0438 \u0432 \u043f\u043e\u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0435 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043f\u043e \u043f\u0440\u0438\u043d\u0430\u0434\u043b\u0435\u0436\u043d\u043e\u0441\u0442\u0438 \u043a \u0442\u043e\u0439 \u0438\u043b\u0438 \u0438\u043d\u043e\u0439 Security Group.\n",(0,r.jsx)(t.em,{children:"\u0412\u0442\u043e\u0440\u0430\u044f"})," \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u0442 \u043d\u0430\u0431\u043e\u0440\u044b \u043f\u0440\u0430\u0432\u0438\u043b, \u043e\u0442\u043d\u043e\u0441\u044f\u0449\u0438\u0435\u0441\u044f \u0442\u043e\u043b\u044c\u043a\u043e \u043a \u043a\u043e\u043d\u043a\u0440\u0435\u0442\u043d\u043e\u0439 Security Group."]})}),"\n",(0,r.jsxs)("table",{children:[(0,r.jsx)("thead",{children:(0,r.jsxs)("tr",{children:[(0,r.jsx)("th",{children:"\u041d\u0430\u0438\u043c\u0435\u043d\u043e\u0432\u0430\u043d\u0438\u0435 \u0446\u0435\u043f\u043e\u0447\u043a\u0438"}),(0,r.jsx)("th",{children:"\u0422\u0438\u043f"}),(0,r.jsx)("th",{children:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435"})]})}),(0,r.jsxs)("tbody",{children:[(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"INGRESS-INPUT"}),(0,r.jsx)("td",{children:"Ingress"}),(0,r.jsx)("td",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:[(0,r.jsx)("i",{children:"\u041f\u0435\u0440\u0432\u0430\u044f"})," \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0442\u043e\u0447\u043a\u043e\u0439 \u0432\u0445\u043e\u0434\u0430 \u0434\u043b\u044f \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0438\u0437 \u0441\u0435\u0442\u0435\u0432\u043e\u0433\u043e \u0441\u0442\u0435\u043a\u0430, \u0432 \u043d\u0435\u0439 \u0443\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u0445\u0443\u043a (input) \u0438\n\u043f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f 0 (filter). \u0422\u0430\u043a \u0436\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u0438 \u0432 \u043f\u043e\u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0435 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043f\u043e \u043f\u0440\u0438\u043d\u0430\u0434\u043b\u0435\u0436\u043d\u043e\u0441\u0442\u0438 \u043a\n\u0442\u043e\u0439 \u0438\u043b\u0438 \u0438\u043d\u043e\u0439 Security Group."]})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"INGRESS-INPUT-$sgName"}),(0,r.jsx)("td",{children:"Ingress"}),(0,r.jsx)("td",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:[(0,r.jsx)("i",{children:"\u0412\u0442\u043e\u0440\u0430\u044f"})," \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u0442 \u043d\u0430\u0431\u043e\u0440\u044b \u043f\u0440\u0430\u0432\u0438\u043b, \u043e\u0442\u043d\u043e\u0441\u044f\u0449\u0438\u0435\u0441\u044f \u0442\u043e\u043b\u044c\u043a\u043e \u043a \u043a\u043e\u043d\u043a\u0440\u0435\u0442\u043d\u043e\u0439 Security Group."]})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"EGRESS-POSTROUTING"}),(0,r.jsx)("td",{children:"Egress"}),(0,r.jsx)("td",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:[(0,r.jsx)("i",{children:"\u041f\u0435\u0440\u0432\u0430\u044f"})," \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0442\u043e\u0447\u043a\u043e\u0439 \u0432\u0445\u043e\u0434\u0430 \u0434\u043b\u044f \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0438\u0437 \u0441\u0435\u0442\u0435\u0432\u043e\u0433\u043e \u0441\u0442\u0435\u043a\u0430, \u0432 \u043d\u0435\u0439 \u0443\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u0445\u0443\u043a (postrouting) \u0438\n\u043f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f 300. \u0422\u0430\u043a \u0436\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u0438 \u0432 \u043f\u043e\u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0435 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043f\u043e \u043f\u0440\u0438\u043d\u0430\u0434\u043b\u0435\u0436\u043d\u043e\u0441\u0442\u0438 \u043a \u0442\u043e\u0439\n\u0438\u043b\u0438 \u0438\u043d\u043e\u0439 Security Group."]})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:(0,r.jsx)("nobr",{children:"EGRESS-POSTROUTING-$sgName"})}),(0,r.jsx)("td",{children:"Egress"}),(0,r.jsx)("td",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:[(0,r.jsx)("i",{children:"\u0412\u0442\u043e\u0440\u0430\u044f"})," \u0446\u0435\u043f\u043e\u0447\u043a\u0430 \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u0442 \u043d\u0430\u0431\u043e\u0440\u044b \u043f\u0440\u0430\u0432\u0438\u043b, \u043e\u0442\u043d\u043e\u0441\u044f\u0449\u0438\u0435\u0441\u044f \u0442\u043e\u043b\u044c\u043a\u043e \u043a \u043a\u043e\u043d\u043a\u0440\u0435\u0442\u043d\u043e\u0439 Security Group."]})})]})]})]}),"\n",(0,r.jsxs)(c.A,{defaultValue:"ingress-input",values:[{label:"INGRESS-INPUT",value:"ingress-input"},{label:"EGRESS-POSTROUTING",value:"egress-postrouting"},{}],children:[(0,r.jsxs)(d.A,{value:"ingress-input",children:[(0,r.jsx)(t.h4,{id:"\u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435",children:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435"}),(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:["\u041f\u0440\u0430\u0432\u0438\u043b\u043e \u043f\u0435\u0440\u0435\u0445\u043e\u0434\u0430 \u0432 \u0446\u0435\u043f\u043e\u0447\u043a\u0443 ",(0,r.jsx)(t.code,{children:"INGRESS-INPUT-sgName"})," \u0441 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u043e\u0439 \u0447\u0442\u043e \u0442\u0440\u0430\u0444\u0438\u043a \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0432\u0445\u043e\u0434\u044f\u0449\u0438\u043c \u0438 \u043f\u0440\u0435\u0434\u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d \u0434\u043b\u044f \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u043e\u0439 Security Group."]})}),(0,r.jsx)(t.h4,{id:"\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",children:"\u041f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b"}),(0,r.jsx)("div",{className:"scrollable-x",children:(0,r.jsxs)("table",{children:[(0,r.jsx)("thead",{children:(0,r.jsxs)("tr",{children:[(0,r.jsx)("th",{children:"\u0428\u0430\u0431\u043b\u043e\u043d \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430"}),(0,r.jsx)("th",{children:"\u0421\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u0430 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430"}),(0,r.jsx)("th",{children:"\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435"}),(0,r.jsx)("th",{children:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435"})]})}),(0,r.jsxs)("tbody",{children:[(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$ConntrackState"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"ct state"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"established,related"})}),(0,r.jsx)("td",{children:(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)(t.p,{children:"\u041e\u043f\u0442\u0435\u0434\u0435\u043b\u044f\u0435\u0442 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u0434\u043b\u044f \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u0430\u043a\u0435\u0442\u043e\u0432, \u0443\u0434\u043e\u0432\u043b\u0435\u0442\u0432\u043e\u0440\u044f\u044e\u0449\u0438\u0445 \u0443\u0441\u043b\u043e\u0432\u0438\u044f\u043c \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u0438 \u0441\u0432\u044f\u0437\u0430\u043d\u043d\u043e\u0433\u043e \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u044f \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f."})})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$CtVerdict"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"accept"})}),(0,r.jsx)("td",{children:(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:["$CtVerdict - \u0443\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442 \u043d\u0430 \u043f\u0440\u0438\u043d\u044f\u0442\u0438\u0435 (accept) \u043f\u0430\u043a\u0435\u0442\u043e\u0432  \u043f\u043e \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u043c \u0443\u0441\u043b\u043e\u0432\u0438\u044f\u043c.\n",(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement",children:"Verdict statement"})]})]})})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$BaseRules"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{}),(0,r.jsxs)("td",{children:[(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)("i",{children:"Base Rules - \u043d\u0430\u0431\u043e\u0440 \u043f\u0440\u0430\u0432\u0438\u043b, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u043f\u0440\u043e\u043f\u0438\u0441\u044b\u0432\u0430\u044e\u0442\u0441\u044f \u0441\u0442\u0430\u0442\u0438\u0447\u043d\u043e \u0438\u0437 \u043a\u043e\u043d\u0444\u0438\u0433\u0440\u0430\u0446\u0438\u043e\u043d\u043d\u043d\u043e\u0433\u043e \u0444\u0430\u0439\u043b\u0430 \u0430\u0433\u0435\u043d\u0442\u0430 \u0434\u043b\u044f \u0442\u043e\u0433\u043e \u0447\u0442\u043e \u0431\u044b \u0432\u0441\u0435\u0433\u0434\u0430 \u0431\u044b\u043b \u0434\u043e\u0441\u0442\u0443\u043f \u0434\u043e \u0432\u044b\u0441\u043e\u043a\u043e\u043a\u0440\u0438\u0442\u0438\u0447\u043d\u044b\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043e\u0432 \u0442\u0430\u043a\u0438\u0445 \u043a\u0430\u043a HBF \u0438 DNS."})}),(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/config-base-rules",children:"Config Base Rules"})]})]})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$RuleType"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"ip"})}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:"\u0423\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c \u043d\u0430 \u0442\u0440\u0430\u0444\u0438\u043a \u0442\u0438\u043f\u0430 IP"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$DstSgroup"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"daddr"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"@${IPSet({sgName})}"})}),(0,r.jsx)("td",{children:"\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0442\u0438\u043f\u0430 string, \u043d\u0435 \u0434\u043e\u043b\u0436\u043d\u043e \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0442\u044c \u0432 \u0441\u0435\u0431\u0435 \u043f\u0440\u043e\u0431\u0435\u043b\u043e\u0432"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$sgName"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:"\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 Security Group"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$Counter"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"counter"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:" packets 0 bytes 0"})}),(0,r.jsx)("td",{children:"\u0421\u0447\u0435\u0442\u0447\u0438\u043a, \u0443\u0447\u0438\u0442\u044b\u0432\u0430\u0435\u0442 \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0441 \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e\u043c \u0431\u0430\u0439\u0442\u043e\u0432 \u043f\u0435\u0440\u0435\u0434\u0430\u043d\u043d\u043e\u0439 \u0438\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u0438 \u0432 \u0440\u0430\u043c\u043a\u0430\u0445 \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u043e\u0439 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043f\u0440\u0430\u0432\u0438\u043b"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$PolicyVerdict"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"policy"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"drop"})}),(0,r.jsxs)("td",{children:[(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)("i",{children:"Policy $Verdict \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u0446\u0435\u043f\u043e\u0447\u0435\u043a \u0441 \u0446\u0435\u043b\u044c\u044e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438 \u0431\u0430\u0437\u043e\u0432\u043e\u0433\u043e \u043f\u0440\u0430\u0432\u0438\u043b\u0430, \u043a\u043e\u0442\u043e\u0440\u043e\u0435 \u0431\u0443\u0434\u0435\u0442 \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u043e \u043a \u043f\u0430\u043a\u0435\u0442\u0443 \u0435\u0441\u043b\u0438 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u043e\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u043d\u0435 \u0443\u0434\u043e\u0432\u043b\u0435\u0442\u0432\u043e\u0440\u0438\u043b\u0438 \u0443\u0441\u043b\u043e\u0432\u0438\u044f. \u041f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e drop. "})}),(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement",children:"Verdict statement"})]})]})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$Verdict"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"goto"})}),(0,r.jsxs)("td",{children:[(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)("i",{children:"\u0422\u0430\u043a \u043a\u0430\u043a \u0434\u0430\u043d\u043d\u043e\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0442\u0438\u043f\u0430 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0442\u043e \u043f\u0435\u0440\u0435\u0445\u043e\u0434 \u043d\u0430 \u0434\u0440\u0443\u0433\u0443\u044e \u0446\u0435\u043f\u043e\u0447\u043a\u0443 \u043f\u0440\u0430\u0432\u0438\u043b \u043f\u0440\u043e\u0438\u0441\u0445\u043e\u0434\u0438\u0442 \u0442\u043e\u043b\u044c\u043a\u043e \u0441 \u043f\u043e\u043c\u043e\u0449\u044c\u044e goto."})}),(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement",children:"Verdict statement"})]})]})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$Hook"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"hook"})}),(0,r.jsx)("td",{children:"input"}),(0,r.jsx)("td",{children:"\u041f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u0445\u0430\u0440\u0430\u043a\u0442\u0435\u0440\u0438\u0437\u0443\u044e\u0449\u0438\u0439 \u0441\u0442\u0430\u0434\u0438\u044e \u043f\u0440\u043e\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u0442\u0440\u0430\u0444\u0438\u043a\u0430"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$HookPriority"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"priority"})}),(0,r.jsx)("td",{children:"0"}),(0,r.jsx)("td",{children:"\u041f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043e\u0434\u043d\u043e\u0433\u043e \u0442\u0438\u043f\u0430"})]})]})]})}),(0,r.jsx)(t.h4,{id:"\u0448\u0430\u0431\u043b\u043e\u043d",children:"\u0428\u0430\u0431\u043b\u043e\u043d"}),(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-hcl",children:"chain INGRESS-INPUT {\n    type filter $Hook $HookPriority; $PolicyVerdict;\n    $ConntrackState $Counter $CtVerdict\n    $BaseRules\n    # **********\n    $RuleType $DstSgroup $Counter $Verdict INGRESS-INPUT-$sgName\n    # **********\n    $Counter\n}\n"})}),(0,r.jsx)(t.h4,{id:"\u043f\u0440\u0438\u043c\u0435\u0440-\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f",children:"\u041f\u0440\u0438\u043c\u0435\u0440 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f"}),(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-hcl",children:"chain INGRESS-INPUT {\n    type filter hook input priority 0; policy drop;\n    ct state established,related counter packets 0 bytes 0 accept\n    ip saddr { 1.1.1.1, 2.2.2.2} accept\n    # **********\n    ip daddr @NetIPv4-exampleSG counter packets   0 bytes 0 goto INGRESS-INPUT-exampleSG\n    # **********\n    counter packets 0 bytes 0\n}\n"})}),(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-hcl",children:"table inet main-1705582480 {\n\n    chain INGRESS-INPUT {\n        type filter hook input priority filter; policy drop;\n        ct state established,related counter packets 0 bytes 0 accept\n        ip saddr { 1.1.1.1, 2.2.2.2} accept\n        # ******\n        ip daddr @NetIPv4-no-routed counter packets   0 bytes 0 goto INGRESS-INPUT-no-routed\n        ip daddr @NetIPv4-exampleSG counter packets   0 bytes 0 goto INGRESS-INPUT-exampleSG\n        counter packets 0 bytes 0\n    }\n\n    chain INGRESS-INPUT-no-routed {\n        # ******\n        counter packets 0 bytes 0 accept\n    }\n\n    chain INGRESS-INPUT-exampleSG {\n        # ******\n        counter packets 0 bytes 0 accept\n    }\n\n}\n"})})]}),(0,r.jsxs)(d.A,{value:"egress-postrouting",children:[(0,r.jsx)(t.h4,{id:"\u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435-1",children:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435"}),(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:["\u041f\u0440\u0430\u0432\u0438\u043b\u043e \u043f\u0435\u0440\u0435\u0445\u043e\u0434\u0430 \u0432 \u0446\u0435\u043f\u043e\u0447\u043a\u0443 ",(0,r.jsx)(t.code,{children:"EGRESS-POSTROUTING-$sgName"})," \u0441 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u043e\u0439 \u0447\u0442\u043e \u0442\u0440\u0430\u0444\u0438\u043a \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0438\u0441\u0445\u043e\u0434\u044f\u0449\u0438\u043c \u0438 \u043f\u0440\u0435\u0434\u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d \u0434\u043b\u044f\n\u0443\u043a\u0430\u0437\u0430\u043d\u043d\u043e\u0439 Security Group."]})}),(0,r.jsx)(t.h4,{id:"\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b-1",children:"\u041f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b"}),(0,r.jsx)("div",{className:"scrollable-x",children:(0,r.jsxs)("table",{children:[(0,r.jsx)("thead",{children:(0,r.jsxs)("tr",{children:[(0,r.jsx)("th",{children:"\u0428\u0430\u0431\u043b\u043e\u043d \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430"}),(0,r.jsx)("th",{children:"\u0421\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u0430 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430"}),(0,r.jsx)("th",{children:"\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435"}),(0,r.jsx)("th",{children:"\u041e\u043f\u0438\u0441\u0430\u043d\u0438\u0435"})]})}),(0,r.jsxs)("tbody",{children:[(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$ConntrackState"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"ct state"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"established,related"})}),(0,r.jsx)("td",{children:(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)(t.p,{children:"\u041e\u043f\u0442\u0435\u0434\u0435\u043b\u044f\u0435\u0442 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u0434\u043b\u044f \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0438 \u043f\u0430\u043a\u0435\u0442\u043e\u0432, \u0443\u0434\u043e\u0432\u043b\u0435\u0442\u0432\u043e\u0440\u044f\u044e\u0449\u0438\u0445 \u0443\u0441\u043b\u043e\u0432\u0438\u044f\u043c \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u0438 \u0441\u0432\u044f\u0437\u0430\u043d\u043d\u043e\u0433\u043e \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u044f \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f."})})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$CtVerdict"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"accept"})}),(0,r.jsx)("td",{children:(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsxs)(t.p,{children:["$CtVerdict - \u0443\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442 \u043d\u0430 \u043f\u0440\u0438\u043d\u044f\u0442\u0438\u0435 (accept) \u043f\u0430\u043a\u0435\u0442\u043e\u0432  \u043f\u043e \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u043c \u0443\u0441\u043b\u043e\u0432\u0438\u044f\u043c.\n",(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement",children:"Verdict statement"})]})]})})})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$BaseRules"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{}),(0,r.jsxs)("td",{children:[(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)("i",{children:"Base Rules - \u043d\u0430\u0431\u043e\u0440 \u043f\u0440\u0430\u0432\u0438\u043b, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u043f\u0440\u043e\u043f\u0438\u0441\u044b\u0432\u0430\u044e\u0442\u0441\u044f \u0441\u0442\u0430\u0442\u0438\u0447\u043d\u043e \u0438\u0437 \u043a\u043e\u043d\u0444\u0438\u0433\u0440\u0430\u0446\u0438\u043e\u043d\u043d\u043d\u043e\u0433\u043e \u0444\u0430\u0439\u043b\u0430 \u0430\u0433\u0435\u043d\u0442\u0430 \u0434\u043b\u044f \u0442\u043e\u0433\u043e \u0447\u0442\u043e \u0431\u044b \u0432\u0441\u0435\u0433\u0434\u0430 \u0431\u044b\u043b \u0434\u043e\u0441\u0442\u0443\u043f \u0434\u043e \u0432\u044b\u0441\u043e\u043a\u043e\u043a\u0440\u0438\u0442\u0438\u0447\u043d\u044b\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043e\u0432 \u0442\u0430\u043a\u0438\u0445 \u043a\u0430\u043a HBF \u0438 DNS."})}),(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/config-base-rules",children:"Config Base Rules"})]})]})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$RuleType"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"ip"})}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:"\u0423\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c \u043d\u0430 \u0442\u0440\u0430\u0444\u0438\u043a \u0442\u0438\u043f\u0430 IP"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$SrcSgroup"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"saddr"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"@${IPSet({sgName})}"})}),(0,r.jsx)("td",{children:"\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0442\u0438\u043f\u0430 string, \u043d\u0435 \u0434\u043e\u043b\u0436\u043d\u043e \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0442\u044c \u0432 \u0441\u0435\u0431\u0435 \u043f\u0440\u043e\u0431\u0435\u043b\u043e\u0432"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$sgName"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:"\u041d\u0430\u0437\u0432\u0430\u043d\u0438\u0435 Security Group"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$Counter"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"counter"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"packets 0 bytes 0"})}),(0,r.jsx)("td",{children:"\u0421\u0447\u0435\u0442\u0447\u0438\u043a, \u0443\u0447\u0438\u0442\u044b\u0432\u0430\u0435\u0442 \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u043d\u044b\u0445 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0441 \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e\u043c \u0431\u0430\u0439\u0442\u043e\u0432 \u043f\u0435\u0440\u0435\u0434\u0430\u043d\u043d\u043e\u0439 \u0438\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u0438 \u0432 \u0440\u0430\u043c\u043a\u0430\u0445 \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u043e\u0439 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043f\u0440\u0430\u0432\u0438\u043b"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$PolicyVerdict"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"policy"})}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"drop"})}),(0,r.jsxs)("td",{children:[(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)("i",{children:"Policy $Verdict \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u0446\u0435\u043f\u043e\u0447\u0435\u043a \u0441 \u0446\u0435\u043b\u044c\u044e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438 \u0431\u0430\u0437\u043e\u0432\u043e\u0433\u043e \u043f\u0440\u0430\u0432\u0438\u043b\u0430, \u043a\u043e\u0442\u043e\u0440\u043e\u0435 \u0431\u0443\u0434\u0435\u0442 \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u043e \u043a \u043f\u0430\u043a\u0435\u0442\u0443 \u0435\u0441\u043b\u0438 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u043e\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u043d\u0435 \u0443\u0434\u043e\u0432\u043b\u0435\u0442\u0432\u043e\u0440\u0438\u043b\u0438 \u0443\u0441\u043b\u043e\u0432\u0438\u044f. \u041f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e drop. "})}),(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement",children:"Verdict statement"})]})]})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$Verdict"}),(0,r.jsx)("td",{}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"goto"})}),(0,r.jsxs)("td",{children:[(0,r.jsx)("div",{className:"text-justify",children:(0,r.jsx)("i",{children:"\u0422\u0430\u043a \u043a\u0430\u043a \u0434\u0430\u043d\u043d\u043e\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f \u0434\u043b\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0442\u0438\u043f\u0430 \u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0442\u043e \u043f\u0435\u0440\u0435\u0445\u043e\u0434 \u043d\u0430 \u0434\u0440\u0443\u0433\u0443\u044e \u0446\u0435\u043f\u043e\u0447\u043a\u0443 \u043f\u0440\u0430\u0432\u0438\u043b \u043f\u0440\u043e\u0438\u0441\u0445\u043e\u0434\u0438\u0442 \u0442\u043e\u043b\u044c\u043a\u043e \u0441 \u043f\u043e\u043c\u043e\u0449\u044c\u044e goto."})}),(0,r.jsxs)("i",{children:["\u041f\u043e\u0434\u0440\u043e\u0431\u043d\u0435\u0435: ",(0,r.jsx)(t.a,{href:"/sgroups/v1.14.0/tech-docs/to-nft/nftables/verdict-statement",children:"Verdict statement"})]})]})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$Hook"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"hook"})}),(0,r.jsx)("td",{children:"input"}),(0,r.jsx)("td",{children:"\u041f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u0445\u0430\u0440\u0430\u043a\u0442\u0435\u0440\u0435\u0437\u0443\u044e\u0449\u0438\u0439 \u0441\u0442\u0430\u0434\u0438\u044e \u043f\u0440\u043e\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u0442\u0440\u0430\u0444\u0438\u043a\u0430"})]}),(0,r.jsxs)("tr",{children:[(0,r.jsx)("td",{children:"$HookPriority"}),(0,r.jsx)("td",{children:(0,r.jsx)(t.code,{children:"priority"})}),(0,r.jsx)("td",{children:"0"}),(0,r.jsx)("td",{children:"\u041f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043e\u0434\u043d\u043e\u0433\u043e \u0442\u0438\u043f\u0430"})]})]})]})}),(0,r.jsx)(t.h4,{id:"\u0448\u0430\u0431\u043b\u043e\u043d-1",children:"\u0428\u0430\u0431\u043b\u043e\u043d"}),(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-hcl",children:"chain EGRESS-POSTROUTING {\n    type filter $Hook $HookPriority; $PolicyVerdict;\n    $ConntrackState $Counter $CtVerdict\n    $BaseRules\n    # **********\n    $RuleType $SrcSgroup $Counter $Verdict EGRESS-POSTROUTING-$sgName\n    # **********\n    $Counter\n}\n"})}),(0,r.jsx)(t.h4,{id:"\u043f\u0440\u0438\u043c\u0435\u0440-\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f-1",children:"\u041f\u0440\u0438\u043c\u0435\u0440 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f"}),(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-hcl",children:"chain EGRESS-POSTROUTING {\n    type filter hook postrouting priority 300; policy drop;\n    ct state established,related counter packets 0 bytes 0 accept\n    ip daddr { 1.1.1.1, 2.2.2.2} accept\n    # **********\n    ip saddr @NetIPv4-exampleSG counter packets 0 bytes 0 goto EGRESS-POSTROUTING-exampleSG\n    # **********\n    counter packets 0 bytes 0\n}\n"})}),(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-hcl",children:"table inet main-1705582480 {\n\n  chain EGRESS-POSTROUTING {\n      type filter hook postrouting priority 300; policy drop;\n      ct state established,related counter packets 0 bytes 0 accept\n      ip daddr { 1.1.1.1, 2.2.2.2} accept\n      # **********\n      ip saddr @NetIPv4-exampleSG counter packets 0 bytes 0 goto EGRESS-POSTROUTING-exampleSG\n      ip saddr @NetIPv4-no-routed counter packets 0 bytes 0 goto EGRESS-POSTROUTING-no-routed\n      counter packets 0 bytes 0\n  }\n\n  chain EGRESS-POSTROUTING-no-routed {\n      # ******\n      counter packets 0 bytes 0 accept\n  }\n\n  chain EGRESS-POSTROUTING-exampleSG {\n      # ******\n      counter packets 0 bytes 0 accept\n  }\n"})})]})]})]})}function x(e={}){const{wrapper:t}={...(0,n.R)(),...e.components};return t?(0,r.jsx)(t,{...e,children:(0,r.jsx)(u,{...e})}):u(e)}},26:(e,t,s)=>{s.d(t,{A:()=>d});s(6540);var r=s(4164);const n={tabItem:"tabItem_Ymn6"};var c=s(4848);function d(e){let{children:t,hidden:s,className:d}=e;return(0,c.jsx)("div",{role:"tabpanel",className:(0,r.A)(n.tabItem,d),hidden:s,children:t})}},7861:(e,t,s)=>{s.d(t,{A:()=>g});var r=s(6540),n=s(4164),c=s(3104),d=s(6347),i=s(205),l=s(7485),a=s(1682),o=s(9466);function h(e){return r.Children.toArray(e).filter((e=>"\n"!==e)).map((e=>{if(!e||(0,r.isValidElement)(e)&&function(e){const{props:t}=e;return!!t&&"object"==typeof t&&"value"in t}(e))return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)}))?.filter(Boolean)??[]}function u(e){const{values:t,children:s}=e;return(0,r.useMemo)((()=>{const e=t??function(e){return h(e).map((e=>{let{props:{value:t,label:s,attributes:r,default:n}}=e;return{value:t,label:s,attributes:r,default:n}}))}(s);return function(e){const t=(0,a.X)(e,((e,t)=>e.value===t.value));if(t.length>0)throw new Error(`Docusaurus error: Duplicate values "${t.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`)}(e),e}),[t,s])}function x(e){let{value:t,tabValues:s}=e;return s.some((e=>e.value===t))}function j(e){let{queryString:t=!1,groupId:s}=e;const n=(0,d.W6)(),c=function(e){let{queryString:t=!1,groupId:s}=e;if("string"==typeof t)return t;if(!1===t)return null;if(!0===t&&!s)throw new Error('Docusaurus error: The <Tabs> component groupId prop is required if queryString=true, because this value is used as the search param name. You can also provide an explicit value such as queryString="my-search-param".');return s??null}({queryString:t,groupId:s});return[(0,l.aZ)(c),(0,r.useCallback)((e=>{if(!c)return;const t=new URLSearchParams(n.location.search);t.set(c,e),n.replace({...n.location,search:t.toString()})}),[c,n])]}function p(e){const{defaultValue:t,queryString:s=!1,groupId:n}=e,c=u(e),[d,l]=(0,r.useState)((()=>function(e){let{defaultValue:t,tabValues:s}=e;if(0===s.length)throw new Error("Docusaurus error: the <Tabs> component requires at least one <TabItem> children component");if(t){if(!x({value:t,tabValues:s}))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${t}" but none of its children has the corresponding value. Available values are: ${s.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);return t}const r=s.find((e=>e.default))??s[0];if(!r)throw new Error("Unexpected error: 0 tabValues");return r.value}({defaultValue:t,tabValues:c}))),[a,h]=j({queryString:s,groupId:n}),[p,f]=function(e){let{groupId:t}=e;const s=function(e){return e?`docusaurus.tab.${e}`:null}(t),[n,c]=(0,o.Dv)(s);return[n,(0,r.useCallback)((e=>{s&&c.set(e)}),[s,c])]}({groupId:n}),m=(()=>{const e=a??p;return x({value:e,tabValues:c})?e:null})();(0,i.A)((()=>{m&&l(m)}),[m]);return{selectedValue:d,selectValue:(0,r.useCallback)((e=>{if(!x({value:e,tabValues:c}))throw new Error(`Can't select invalid tab value=${e}`);l(e),h(e),f(e)}),[h,f,c]),tabValues:c}}var f=s(2303);const m={tabList:"tabList__CuJ",tabItem:"tabItem_LNqP"};var b=s(4848);function S(e){let{className:t,block:s,selectedValue:r,selectValue:d,tabValues:i}=e;const l=[],{blockElementScrollPositionUntilNextRender:a}=(0,c.a_)(),o=e=>{const t=e.currentTarget,s=l.indexOf(t),n=i[s].value;n!==r&&(a(t),d(n))},h=e=>{let t=null;switch(e.key){case"Enter":o(e);break;case"ArrowRight":{const s=l.indexOf(e.currentTarget)+1;t=l[s]??l[0];break}case"ArrowLeft":{const s=l.indexOf(e.currentTarget)-1;t=l[s]??l[l.length-1];break}}t?.focus()};return(0,b.jsx)("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,n.A)("tabs",{"tabs--block":s},t),children:i.map((e=>{let{value:t,label:s,attributes:c}=e;return(0,b.jsx)("li",{role:"tab",tabIndex:r===t?0:-1,"aria-selected":r===t,ref:e=>l.push(e),onKeyDown:h,onClick:o,...c,className:(0,n.A)("tabs__item",m.tabItem,c?.className,{"tabs__item--active":r===t}),children:s??t},t)}))})}function v(e){let{lazy:t,children:s,selectedValue:n}=e;const c=(Array.isArray(s)?s:[s]).filter(Boolean);if(t){const e=c.find((e=>e.props.value===n));return e?(0,r.cloneElement)(e,{className:"margin-top--md"}):null}return(0,b.jsx)("div",{className:"margin-top--md",children:c.map(((e,t)=>(0,r.cloneElement)(e,{key:t,hidden:e.props.value!==n})))})}function y(e){const t=p(e);return(0,b.jsxs)("div",{className:(0,n.A)("tabs-container",m.tabList),children:[(0,b.jsx)(S,{...e,...t}),(0,b.jsx)(v,{...e,...t})]})}function g(e){const t=(0,f.A)();return(0,b.jsx)(y,{...e,children:h(e.children)},String(t))}}}]);