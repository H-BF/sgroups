"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9424],{4545:(e,r,s)=>{s.d(r,{Ay:()=>d});var t=s(4848),n=s(8453);function o(e){const{Details:r}={...(0,n.R)(),...e.components};return r||function(e,r){throw new Error("Expected "+(r?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,t.jsxs)(r,{children:[(0,t.jsx)("summary",{children:e.data.description}),(0,t.jsxs)("ul",{children:[(0,t.jsxs)("li",{children:["HTTP code: ",e.data.httpCode]}),(0,t.jsxs)("li",{children:["gRPC code: ",e.data.grpcCode]}),(0,t.jsxs)("li",{children:["gRPC number: ",e.data.grpcNumber]})]})]})}function d(e={}){const{wrapper:r}={...(0,n.R)(),...e.components};return r?(0,t.jsx)(r,{...e,children:(0,t.jsx)(o,{...e})}):o(e)}},6477:(e,r,s)=>{s.r(r),s.d(r,{assets:()=>p,contentTitle:()=>a,default:()=>m,frontMatter:()=>i,metadata:()=>h,toc:()=>u});var t=s(4848),n=s(8453),o=s(9612),d=s(6583),c=s(4545),l=s(7097);const i={id:"networks"},a="POST /v1/list/networks",h={id:"tech-docs/sgroups/api/v1/networks",title:"POST /v1/list/networks",description:"\u042d\u0442\u043e\u0442 \u043c\u0435\u0442\u043e\u0434 \u043e\u0442\u043e\u0431\u0440\u0430\u0436\u0430\u0435\u0442 \u0441\u043f\u0438\u0441\u043e\u043a \u043f\u043e\u0434\u0441\u0435\u0442\u0435\u0439 (networks) \u0438 \u0438\u0445 IP, \u0432 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0438\u0438 \u0441 \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u043c \u0441\u043f\u0438\u0441\u043a\u043e\u043c \u0438\u043c\u0435\u043d \u043f\u043e\u0434\u0441\u0435\u0442\u0435\u0439 (networks).",source:"@site/versioned_docs/version-v1.14.0/tech-docs/sgroups/api/v1/networks.mdx",sourceDirName:"tech-docs/sgroups/api/v1",slug:"/tech-docs/sgroups/api/v1/networks",permalink:"/sgroups/tech-docs/sgroups/api/v1/networks",draft:!1,unlisted:!1,tags:[],version:"v1.14.0",frontMatter:{id:"networks"},sidebar:"techDocs",previous:{title:"GET /v1/\\{address\\}/sg",permalink:"/sgroups/tech-docs/sgroups/api/v1/address-sg"},next:{title:"GET /v1/sg/\\{sgName\\}/subnets",permalink:"/sgroups/tech-docs/sgroups/api/v1/subnets"}},p={},u=[{value:"\u0412\u0445\u043e\u0434\u043d\u044b\u0435 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",id:"\u0432\u0445\u043e\u0434\u043d\u044b\u0435-\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",level:4}];function x(e){const r={a:"a",code:"code",h1:"h1",h4:"h4",mermaid:"mermaid",p:"p",pre:"pre",...(0,n.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(r.h1,{id:"post-v1listnetworks",children:"POST /v1/list/networks"}),"\n",(0,t.jsx)("div",{className:"text-justify",children:(0,t.jsx)(r.p,{children:"\u042d\u0442\u043e\u0442 \u043c\u0435\u0442\u043e\u0434 \u043e\u0442\u043e\u0431\u0440\u0430\u0436\u0430\u0435\u0442 \u0441\u043f\u0438\u0441\u043e\u043a \u043f\u043e\u0434\u0441\u0435\u0442\u0435\u0439 (networks) \u0438 \u0438\u0445 IP, \u0432 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0438\u0438 \u0441 \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u043c \u0441\u043f\u0438\u0441\u043a\u043e\u043c \u0438\u043c\u0435\u043d \u043f\u043e\u0434\u0441\u0435\u0442\u0435\u0439 (networks)."})}),"\n",(0,t.jsx)("div",{className:"text-justify",children:(0,t.jsxs)(r.p,{children:["\u0411\u043e\u043b\u0435\u0435 \u043f\u043e\u0434\u0440\u043e\u0431\u043d\u043e \u043f\u043e \u043e\u0440\u0433\u0430\u043d\u0438\u0437\u0430\u0446\u0438\u0438 \u0411\u0414 \u043c\u043e\u0436\u043d\u043e \u043f\u043e\u0441\u043c\u043e\u0442\u0440\u0435\u0442\u044c ",(0,t.jsx)(r.a,{href:"/sgroups/tech-docs/sgroups/database#tbl_network",children:"\u0437\u0434\u0435\u0441\u044c"}),"."]})}),"\n",(0,t.jsx)(r.h4,{id:"\u0432\u0445\u043e\u0434\u043d\u044b\u0435-\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b",children:"\u0412\u0445\u043e\u0434\u043d\u044b\u0435 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b"}),"\n",(0,t.jsx)("ul",{children:(0,t.jsxs)("li",{children:[(0,t.jsx)(r.code,{children:"neteworkNames[]"})," - ",l.x.networkNames.short]})}),"\n",(0,t.jsx)("div",{className:"scrollable-x",children:(0,t.jsxs)("table",{children:[(0,t.jsx)("thead",{children:(0,t.jsxs)("tr",{children:[(0,t.jsx)("th",{rowSpan:"2",children:"\u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435"}),(0,t.jsx)("th",{rowSpan:"2",children:"\u043e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u044c"}),(0,t.jsx)("th",{rowSpan:"2",children:"\u0442\u0438\u043f \u0434\u0430\u043d\u043d\u044b\u0445"}),(0,t.jsx)("th",{rowSpan:"2",children:"\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e"})]})}),(0,t.jsx)("tbody",{children:(0,t.jsxs)("tr",{children:[(0,t.jsx)("td",{children:"neteworkNames[]"}),(0,t.jsx)("td",{children:"\u0434\u0430"}),(0,t.jsx)("td",{children:"Object[]"}),(0,t.jsx)("td",{})]})})]})}),"\n",(0,t.jsx)("h4",{className:"custom-heading",children:"\u041f\u0440\u0438\u043c\u0435\u0440 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f"}),"\n",(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",children:"curl '127.0.0.1:9007/v1/list/networks' \\\n--header 'Content-Type: application/json' \\\n--data '{\n    \"neteworkNames\": [\"network-example\"]\n}'\n"})}),"\n",(0,t.jsx)("h4",{className:"custom-heading",children:"\u0412\u044b\u0445\u043e\u0434\u043d\u044b\u0435 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b"}),"\n",(0,t.jsxs)("ul",{children:[(0,t.jsxs)("li",{children:[(0,t.jsx)(r.code,{children:"$node.networks[]"})," - ",l.x.rules.short]}),(0,t.jsxs)("li",{children:[(0,t.jsx)(r.code,{children:"$node.networks[].name"})," - ",l.x.nw.short]}),(0,t.jsxs)("li",{children:[(0,t.jsx)(r.code,{children:"$node.networks[].network"})," - ",l.x.networkObject.short]}),(0,t.jsxs)("li",{children:[(0,t.jsx)(r.code,{children:"$node.networks[].network.CIDR"})," - ",l.x.networks.short]})]}),"\n",(0,t.jsx)("div",{className:"scrollable-x",children:(0,t.jsxs)("table",{children:[(0,t.jsx)("thead",{children:(0,t.jsxs)("tr",{children:[(0,t.jsx)("th",{children:"\u043d\u0430\u0437\u0432\u0430\u043d\u0438\u0435"}),(0,t.jsx)("th",{children:"\u0442\u0438\u043f \u0434\u0430\u043d\u043d\u044b\u0445"})]})}),(0,t.jsxs)("tbody",{children:[(0,t.jsxs)("tr",{children:[(0,t.jsx)("td",{children:"$node.networks[]"}),(0,t.jsx)("td",{children:"Object[]"})]}),(0,t.jsxs)("tr",{children:[(0,t.jsx)("td",{children:"$node.networks[].name"}),(0,t.jsx)("td",{children:"String"})]}),(0,t.jsxs)("tr",{children:[(0,t.jsx)("td",{children:"$node.networks[].network"}),(0,t.jsx)("td",{children:"Object"})]}),(0,t.jsxs)("tr",{children:[(0,t.jsx)("td",{children:"$node.networks[].network.CIDR"}),(0,t.jsx)("td",{children:"String"})]})]})]})}),"\n",(0,t.jsx)("h4",{className:"custom-heading",children:"\u041f\u0440\u0438\u043c\u0435\u0440 \u043e\u0442\u0432\u0435\u0442\u0430"}),"\n",(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",children:'{\n    "networks": [{\n        "network": "network-example",\n        "ICMP": {\n                "CIDR": "10.150.0.220/32"\n            },\n    }]\n}\n'})}),"\n",(0,t.jsx)("h4",{className:"custom-heading",children:"\u0412\u043e\u0437\u043c\u043e\u0436\u043d\u044b\u0435 \u043e\u0448\u0438\u0431\u043a\u0438 API"}),"\n",(0,t.jsx)(c.Ay,{data:d.L.internal}),"\n",(0,t.jsx)(c.Ay,{data:d.L.not_found}),"\n",(0,t.jsx)("h4",{className:"custom-heading",children:"\u0414\u0438\u0430\u0433\u0440\u0430\u043c\u043c\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043e\u0432\u0430\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u0438"}),"\n",(0,t.jsx)(o.S,{children:(0,t.jsx)(r.mermaid,{value:"sequenceDiagram\nparticipant user as User\nparticipant server as Server\nparticipant db as Database\n\nuser->>server: \u041e\u0442\u043e\u0431\u0440\u0430\u0437\u0438\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b\u0445 \u0441\u0435\u0442\u0435\u0439\n\nalt \u041e\u0448\u0438\u0431\u043a\u0430 \u0432 \u0437\u0430\u043f\u0440\u043e\u0441\u0435\n    server--\x3e>user: \u041f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u043e\u0448\u0438\u0431\u043a\u0443 \u0432 \u0437\u0430\u043f\u0440\u043e\u0441\u0435\nend\n\nserver->>db: \u041e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c \u0437\u0430\u043f\u0440\u043e\u0441\ndb->>db: \u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0432\u0445\u043e\u0434\u044f\u0449\u0435\u0433\u043e \u0437\u0430\u043f\u0440\u043e\u0441\u0430\n\nalt \u0423\u043a\u0430\u0437\u0430\u043d\u043e \u043d\u0435\u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u044e\u0449\u0435\u0433\u043e \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430\n    db--\x3e>server: \u041e\u0442\u0432\u0435\u0442 \u0441 \u043e\u0448\u0438\u0431\u043a\u043e\u0439\n    server--\x3e>user: \u041f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u043e\u0448\u0438\u0431\u043a\u0443 \u0432 \u0437\u0430\u043f\u0440\u043e\u0441\u0435\nend\n\ndb--\x3e>server: \u041e\u0442\u0432\u0435\u0442 \u0441\u043e \u0441\u043f\u0438\u0441\u043a\u043e\u043c \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b\u0445 \u0441\u0435\u0442\u0435\u0439 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0439 \u0437\u0430\u043f\u0440\u043e\u0441\u0443\nserver--\x3e>user: \u0421\u043f\u0438\u0441\u043e\u043a \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b\u0445 \u0441\u0435\u0442\u0435\u0439 \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0439 \u0437\u0430\u043f\u0440\u043e\u0441\u0443"})})]})}function m(e={}){const{wrapper:r}={...(0,n.R)(),...e.components};return r?(0,t.jsx)(r,{...e,children:(0,t.jsx)(x,{...e})}):x(e)}},7097:(e,r,s)=>{s.d(r,{x:()=>t});const t={syncOp:{short:"\u041f\u043e\u043b\u0435 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u044f\u044e\u0449\u0435\u0435 \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0435 \u0441 \u0434\u0430\u043d\u043d\u044b\u043c\u0438 \u0438\u0437 \u0437\u0430\u043f\u0440\u043e\u0441\u0430.",full:""},traffic:{short:"\u041f\u043e\u043b\u0435 \u043e\u043f\u0438\u0441\u044b\u0432\u0430\u044e\u0449\u0438\u0439 \u043d\u0430\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0442\u0440\u0430\u0444\u0438\u043a\u0430.",full:""},transport:{short:"\u041f\u0440\u043e\u0442\u043e\u043a\u043e\u043b L3/L4 \u0443\u0440\u043e\u0432\u043d\u044f \u043c\u043e\u0434\u0435\u043b\u0438 OSI.",full:""},log:{short:"\u0412\u043a\u043b\u044e\u0447\u0438\u0442\u044c/\u043e\u0442\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u043b\u043e\u0433\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435.",full:""},trace:{short:"\u0412\u043a\u043b\u044e\u0447\u0438\u0442\u044c/\u043e\u0442\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u0442\u0440\u0430\u0441\u0441\u0438\u0440\u043e\u0432\u043a\u0443.",full:""},ports:{short:"\u0411\u043b\u043e\u043a \u043e\u043f\u0438\u0441\u044b\u0432\u0430\u044e\u0449\u0438\u0439 \u043d\u0430\u0431\u043e\u0440 \u043f\u0430\u0440 \u043f\u043e\u0440\u0442\u043e\u0432 (src-dst).",full:""},srcPorts:{short:"\u041d\u0430\u0431\u043e\u0440 \u043e\u0442\u043a\u0440\u044b\u0442\u044b\u0445 \u043f\u043e\u0440\u0442\u043e\u0432 \u043e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u0435\u043b\u044f.",full:""},dstPorts:{short:"\u041d\u0430\u0431\u043e\u0440 \u043e\u0442\u043a\u0440\u044b\u0442\u044b\u0445 \u043f\u043e\u0440\u0442\u043e\u0432 \u043f\u043e\u043b\u0443\u0447\u0430\u0442\u0435\u043b\u044f",full:""},apiIcmp:{short:"\u0421\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u0430, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0430\u044f \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u0441\u043e\u0437\u0434\u0430\u0432\u0430\u0435\u043c\u044b\u0445 \u043f\u0440\u0430\u0432\u0438\u043b \u0442\u0438\u043f\u0430 ICMP.",full:""},icmpV:{short:"\u0412\u0435\u0440\u0441\u0438\u044f IP \u0434\u043b\u044f ICMP (IPv4 \u0438\u043b\u0438 IPv6).",full:""},icmpTypes:{short:"\u0421\u043f\u0438\u0441\u043e\u043a, \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u044f\u044e\u0449\u0438\u0439 \u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b\u0435 \u0442\u0438\u043f\u044b ICMP \u0437\u0430\u043f\u0440\u043e\u0441\u043e\u0432.",full:""},sgroupSet:{short:"\u0421\u043f\u0438\u0441\u043e\u043a, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0438\u0439 \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u044f Security Group(s).",full:""},sg:{short:"Security Group, \u0441 \u043a\u043e\u0442\u043e\u0440\u043e\u0439 \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e\u0442\u0441\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430 \u0432\u0437\u0430\u0438\u043c\u043e\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044f.",full:""},sgLocal:{short:"Security Group \u043e\u0442\u043d\u043e\u0441\u0438\u0442\u0435\u043b\u044c\u043d\u043e \u043a\u043e\u0442\u043e\u0440\u043e\u0439 \u0440\u0430\u0441\u0441\u043c\u0430\u0442\u0440\u0438\u0432\u0430\u044e\u0442\u0441\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430.",full:""},description:{short:"\u0424\u043e\u0440\u043c\u0430\u043b\u044c\u043d\u043e\u0435 \u0442\u0435\u043a\u0441\u0442\u043e\u0432\u043e\u0435 \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435.",full:""},rules:{short:"\u0421\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u0430, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0430\u044f \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u0441\u043e\u0437\u0434\u0430\u0432\u0430\u0435\u043c\u044b\u0445 \u043f\u0440\u0430\u0432\u0438\u043b.",full:""},nftRuleType:{short:"\u0425\u0430\u0440\u0430\u043a\u0442\u0435\u0440\u0438\u0441\u0442\u0438\u043a\u0430 \u043e\u043f\u0438\u0441\u044b\u0432\u0430\u044e\u0449\u0430\u044f, \u0447\u0442\u043e \u043f\u0440\u0438\u043d\u0438\u043c\u0430\u0435\u0442\u0441\u044f \u0442\u0440\u0430\u0444\u0438\u043a \u0442\u0438\u043f\u0430 ip.",full:""},nftCounter:{short:"\u0421\u0447\u0435\u0442\u0447\u0438\u043a \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u0430 \u0431\u0430\u0439\u0442\u043e\u0432 \u0438 \u043f\u0430\u043a\u0435\u0442\u043e\u0432.",full:""},nftRuleVerdict:{short:"\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u0438\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430, \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u044f\u044e\u0449\u0438\u0439 \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0435, \u043a\u043e\u0442\u043e\u0440\u043e\u0435 \u0431\u0443\u0434\u0435\u0442 \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u043e \u043a \u043f\u0430\u043a\u0435\u0442\u0443.",full:""},terraformModule:{short:"",full:"Terraform module \u043f\u0440\u0435\u0434\u0441\u0442\u0430\u0432\u043b\u044f\u0435\u0442 \u0441\u043e\u0431\u043e\u0439 \u0432\u044b\u0441\u043e\u043a\u043e\u0443\u0440\u043e\u0432\u043d\u0435\u0432\u0443\u044e \u0430\u0431\u0441\u0442\u0440\u0430\u043a\u0446\u0438\u044e \u043d\u0430\u0434 terraform resources, \u043a\u043e\u0442\u043e\u0440\u0430\u044f\n        \u0443\u043f\u0440\u043e\u0449\u0430\u0435\u0442 \u0440\u0430\u0431\u043e\u0442\u0443 \u0441 \u0440\u0435\u0441\u0443\u0440\u0441\u0430\u043c\u0438 Terraform, \u0441\u043a\u0440\u044b\u0432\u0430\u044f \u0441\u043b\u043e\u0436\u043d\u043e\u0441\u0442\u044c \u0438\u0445 \u043d\u0435\u043f\u043e\u0441\u0440\u0435\u0434\u0441\u0442\u0432\u0435\u043d\u043d\u043e\u0433\u043e \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f. \u041e\u043d \u043f\u0440\u0435\u0434\u043b\u0430\u0433\u0430\u0435\u0442\n        \u043f\u0440\u043e\u0441\u0442\u043e\u0439 \u0438 \u043f\u043e\u043d\u044f\u0442\u043d\u044b\u0439 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441 \u0434\u043b\u044f \u0432\u0437\u0430\u0438\u043c\u043e\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044f, \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u044f \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044f\u043c \u043b\u0435\u0433\u043a\u043e \u0438\u043d\u0442\u0435\u0433\u0440\u0438\u0440\u043e\u0432\u0430\u0442\u044c\u0441\u044f \u0438 \u0443\u043f\u0440\u0430\u0432\u043b\u044f\u0442\u044c\n        \u043a\u043e\u043c\u043f\u043e\u043d\u0435\u043d\u0442\u0430\u043c\u0438 \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u0431\u0435\u0437 \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e\u0441\u0442\u0438 \u0433\u043b\u0443\u0431\u043e\u043a\u043e \u043f\u043e\u0433\u0440\u0443\u0436\u0430\u0442\u044c\u0441\u044f \u0432 \u0434\u0435\u0442\u0430\u043b\u0438 \u043a\u0430\u0436\u0434\u043e\u0433\u043e \u0440\u0435\u0441\u0443\u0440\u0441\u0430."},terraformResource:{short:"",full:"Terraform resource \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043a\u043b\u044e\u0447\u0435\u0432\u044b\u043c \u044d\u043b\u0435\u043c\u0435\u043d\u0442\u043e\u043c \u0432 Terraform, \u043f\u0440\u0435\u0434\u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u043d\u044b\u043c \u0434\u043b\u044f \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u044f \u0440\u0430\u0437\u043b\u0438\u0447\u043d\u044b\u043c\u0438\n        \u0430\u0441\u043f\u0435\u043a\u0442\u0430\u043c\u0438 \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u0447\u0435\u0440\u0435\u0437 \u043a\u043e\u0434. \u041e\u043d \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u0435\u0442 \u0437\u0430\u0434\u0430\u0432\u0430\u0442\u044c, \u043d\u0430\u0441\u0442\u0440\u0430\u0438\u0432\u0430\u0442\u044c \u0438 \u0443\u043f\u0440\u0430\u0432\u043b\u044f\u0442\u044c \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u043d\u044b\u043c\u0438\n        \u043a\u043e\u043c\u043f\u043e\u043d\u0435\u043d\u0442\u0430\u043c\u0438 \u0431\u0435\u0437 \u043f\u0440\u0438\u0432\u044f\u0437\u043a\u0438 \u043a \u0438\u0445 \u043a\u043e\u043d\u043a\u0440\u0435\u0442\u043d\u044b\u043c \u0442\u0438\u043f\u0430\u043c, \u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0432\u0430\u044f \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0437\u0430\u0446\u0438\u044e \u0440\u0430\u0437\u0432\u0435\u0440\u0442\u044b\u0432\u0430\u043d\u0438\u044f \u0438 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u043a\u0438\n        \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u0441\u043e\u0433\u043b\u0430\u0441\u043d\u043e \u043f\u043e\u0434\u0445\u043e\u0434\u0443 Infrastructure as Code (IaC)."},cidrSet:{short:"\u0421\u043f\u0438\u0441\u043e\u043a, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0438\u0439 \u043f\u043e\u0434\u0441\u0435\u0442\u0438 \u0442\u0438\u043f\u0430 IP.",full:""},fqdnSet:{short:"\u0421\u043f\u0438\u0441\u043e\u043a, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0438\u0439 FQDN \u0437\u0430\u043f\u0438\u0441\u0438.",full:""},fqdn:{short:"\u041f\u043e\u043b\u043d\u043e\u0435 \u0434\u043e\u043c\u0435\u043d\u043d\u043e\u0435 \u0438\u043c\u044f (FQDN), \u0434\u043b\u044f \u043a\u043e\u0442\u043e\u0440\u043e\u0433\u043e \u043f\u0440\u0438\u043c\u0435\u043d\u044f\u0435\u0442\u0441\u044f \u0434\u0430\u043d\u043d\u043e\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u043e.",full:""},l7ProtocolList:{short:"\u0421\u043f\u0438\u0441\u043e\u043a \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b\u043e\u0432 L7 \u0443\u0440\u043e\u0432\u043d\u044f \u043c\u043e\u0434\u0435\u043b\u0438 OSI.",full:""},networks:{short:"\u041c\u0430\u0441\u0441\u0438\u0432/\u0421\u043f\u0438\u0441\u043e\u043a \u043f\u043e\u0434\u0441\u0435\u0442\u0435\u0439 \u0442\u0438\u043f\u0430 IP.",full:""},nw:{short:"\u0418\u043c\u044f \u043f\u043e\u0434\u0441\u0435\u0442\u0438",full:""},networkNames:{short:"\u041c\u0430\u0441\u0441\u0438\u0432/\u0421\u043f\u0438\u0441\u043e\u043a \u0438\u043c\u0435\u043d \u043f\u043e\u0434\u0441\u0435\u0442\u0435\u0439",full:""},networkObject:{short:"\u0421\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u0430, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0430\u044f \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u0441\u0435\u0442\u0438",full:""},cidr:{short:"\u041f\u043e\u0434\u0441\u0435\u0442\u044c \u0442\u0438\u043f\u0430 IP.",full:""},srcDstCidr:{short:"CIDR, \u0441 \u043a\u043e\u0442\u043e\u0440\u043e\u0439 \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e\u0442\u0441\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430 \u0432\u0437\u0430\u0438\u043c\u043e\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044f.",full:""},terraformItems:{short:"\u0421\u043f\u0438\u0441\u043e\u043a \u0440\u0435\u0441\u0443\u0440\u0441\u043e\u0432 \u0441\u043e\u0437\u0434\u0430\u0432\u0430\u0435\u043c\u044b\u0435 terraform \u0440\u0435\u0441\u0443\u0440\u0441\u043e\u043c.",full:""},terraformRuleName:{short:"\u0423\u043d\u0438\u043a\u0430\u043b\u044c\u043d\u043e\u0435 \u0438\u043c\u044f \u0441\u043e\u0437\u0434\u0430\u0432\u0430\u0435\u043c\u043e\u0433\u043e \u0440\u0435\u0441\u0443\u0440\u0441\u0430.",full:""},defaultAction:{short:"\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u0435 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e.",full:""},action:{short:"\u0414\u0435\u0439\u0441\u0442\u0432\u0438\u0435 \u0434\u043b\u044f \u043f\u0430\u043a\u0435\u0442\u043e\u0432 \u0432 \u0441\u0444\u043e\u0440\u043c\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u043f\u0440\u0430\u0432\u0438\u043b \u0432 \u0446\u0435\u043f\u043e\u0447\u043a\u0435.",full:""},priority:{short:"\u041f\u043e\u043b\u0435 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u044f\u044e\u0449\u0435\u0435 \u043f\u043e\u0440\u044f\u0434\u043e\u043a \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u0438\u044f \u043f\u0440\u0430\u0432\u0438\u043b \u0432 \u0446\u0435\u043f\u043e\u0447\u043a\u0435.",full:""},priorityst:{short:"\u0421\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u0430, \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0449\u0430\u044f \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u043f\u043e\u0440\u044f\u0434\u043a\u0430 \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u0438\u044f \u043f\u0440\u0430\u0432\u0438\u043b \u0432 \u0446\u0435\u043f\u043e\u0447\u043a\u0435.",full:""}}},6583:(e,r,s)=>{s.d(r,{L:()=>t});const t={ok:{grpcCode:"OK",httpCode:"",grpcNumber:"0",description:"\u0423\u0441\u043f\u0435\u0448\u043d\u044b\u0439 \u043e\u0442\u0432\u0435\u0442"},cancelled:{grpcCode:"CANCELLED",httpCode:"",grpcNumber:"1",description:"\u041e\u043f\u0435\u0440\u0430\u0446\u0438\u044f \u0431\u044b\u043b\u0430 \u043e\u0442\u043c\u0435\u043d\u0435\u043d\u0430"},unknown:{grpcCode:"UNKNOWN",httpCode:"",grpcNumber:"2",description:"\u041d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0432\u0435\u043d\u0430\u044f \u043e\u0448\u0438\u0431\u043a\u0430"},invalid_argument:{grpcCode:"INVALID_ARGUMENT",httpCode:"400",grpcNumber:"3",description:"\u041f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u0443\u043a\u0430\u0437\u0430\u043b \u043d\u0435\u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f \u0430\u0433\u0440\u0443\u043c\u0435\u043d\u0442\u043e\u0432"},deadline_exceeded:{grpcCode:"DEADLINE_EXCEEDED",httpCode:"",grpcNumber:"4",description:"\u0417\u0430\u043f\u0440\u043e\u0441 \u043d\u0435 \u0443\u0441\u043f\u0435\u043b \u0432\u043e\u0432\u0440\u0435\u043c\u044f \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u0430\u0442\u044c \u0438\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u044e"},not_found:{grpcCode:"NOT_FOUND",httpCode:"404",grpcNumber:"5",description:"\u041d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d \u043c\u0435\u0442\u043e\u0434"},already_exists:{grpcCode:"ALREADY_EXISTS",httpCode:"",grpcNumber:"6",description:"\u0414\u0430\u043d\u043d\u044b\u0439 \u043e\u0431\u044a\u0435\u043a\u0442 \u0443\u0436\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442"},permition_denied:{grpcCode:"PERMISSION_DENIED",httpCode:"",grpcNumber:"7",description:"\u0414\u043e\u0441\u0442\u0443\u043f \u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d"},resource_exhausted:{grpcCode:"RESOURCE_EXHAUSTED",httpCode:"",grpcNumber:"8",description:"\u041d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043c\u0435\u0441\u0442\u0430 \u0434\u043b\u044f \u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u0438\u044f \u0438\u043d\u0444\u043e\u0440\u043c\u0430\u0446\u0438\u0438"},failed_precondition:{grpcCode:"FAILED_PRECONDITION",httpCode:"",grpcNumber:"9",description:"\u041d\u0435 \u0432\u044b\u0431\u043e\u043b\u043d\u0435\u043d\u044b \u0443\u0441\u043f\u043e\u043b\u043e\u0432\u0438\u044f \u043f\u0440\u0435\u0434\u0432\u0430\u0440\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0433\u043e \u0437\u0430\u043f\u0440\u043e\u0441\u0430"},aborted:{grpcCode:"ABORTED",httpCode:"",grpcNumber:"10",description:"\u041e\u043f\u0435\u0440\u0430\u0446\u0438\u044f \u0431\u044b\u043b\u0430 \u043e\u0442\u043c\u0435\u043d\u0435\u043d\u0430"},out_of_range:{grpcCode:"OUT_OF_RANGE",httpCode:"",grpcNumber:"11",description:"\u041e\u043f\u0435\u0440\u0430\u0446\u0438\u044f \u043f\u0440\u0435\u0432\u044b\u0441\u0438\u043b\u0430 \u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435"},unimplemented:{grpcCode:"UNIMPLEMENTED",httpCode:"",grpcNumber:"12",description:"\u0414\u0430\u043d\u043d\u0430\u044f \u043e\u043f\u0435\u0440\u0430\u0446\u0438\u0438\u044f \u043d\u0435 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044f \u0438\u043b\u0438 \u043d\u0435 \u0431\u044b\u043b\u0430 \u0440\u0435\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u0430"},internal:{grpcCode:"INTERNAL",httpCode:"500",grpcNumber:"13",description:"\u041e\u0448\u0438\u0431\u043a\u0430 \u0432 \u0443\u043a\u0430\u0437\u0430\u043d\u043d\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445"},unavailable:{grpcCode:"UNAVAILABLE",httpCode:"",grpcNumber:"14",description:"\u0421\u0435\u0440\u0432\u0438\u0441 \u0432\u0440\u0435\u043c\u0435\u043d\u043d\u043e \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d"},data_loss:{grpcCode:"NOT_FDATA_LOSSOUND",httpCode:"",grpcNumber:"15",description:"\u0414\u0430\u043d\u043d\u044b\u0435 \u0431\u044b\u043b\u0438 \u043f\u043e\u0432\u0440\u0435\u0436\u0434\u0435\u043d\u044b \u0438\u043b\u0438 \u0443\u0442\u0435\u0440\u044f\u043d\u044b"},unauthenticated:{grpcCode:"UNAUTHENTICATED",httpCode:"",grpcNumber:"16",description:"\u0423 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044f \u043d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043f\u0440\u0430\u0432 \u0434\u043b\u044f \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f \u044d\u0442\u043e\u0433\u043e \u043c\u0435\u0442\u043e\u0434\u0430"}}}}]);