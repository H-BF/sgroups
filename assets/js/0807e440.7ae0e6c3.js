"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9375],{1146:(e,r,s)=>{s.r(r),s.d(r,{assets:()=>a,contentTitle:()=>i,default:()=>d,frontMatter:()=>n,metadata:()=>l,toc:()=>o});var t=s(4848),c=s(8453);const n={id:"spec-terraform"},i="\u0417\u0430\u043f\u0443\u0441\u043a",l={id:"tech-docs/terraform/spec-terraform",title:"\u0417\u0430\u043f\u0443\u0441\u043a",description:"\u041f\u043e\u0441\u043b\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430, \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u043c\u043e\u0436\u0435\u0442 \u043f\u0440\u0438\u0441\u0442\u0443\u043f\u0430\u0442\u044c \u043a \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u044e \u0441\u043e\u0431\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0445 sgroups. \u0412 \u043a\u0430\u0447\u0435\u0441\u0442\u0432\u0435 \u043e\u0442\u043f\u0440\u0430\u0432\u043d\u043e\u0439 \u0442\u043e\u0447\u043a\u0438,",source:"@site/versioned_docs/version-v1.13.0/tech-docs/terraform/spec.mdx",sourceDirName:"tech-docs/terraform",slug:"/tech-docs/terraform/spec-terraform",permalink:"/sgroups/v1.13.0/tech-docs/terraform/spec-terraform",draft:!1,unlisted:!1,tags:[],version:"v1.13.0",frontMatter:{id:"spec-terraform"},sidebar:"techDocs",previous:{title:"\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430",permalink:"/sgroups/v1.13.0/tech-docs/terraform/provider-terraform"},next:{title:"Networks",permalink:"/sgroups/v1.13.0/tech-docs/rule-configuration/networks"}},a={},o=[];function p(e){const r={code:"code",em:"em",h1:"h1",p:"p",pre:"pre",...(0,c.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(r.h1,{id:"\u0437\u0430\u043f\u0443\u0441\u043a",children:"\u0417\u0430\u043f\u0443\u0441\u043a"}),"\n",(0,t.jsx)("div",{children:(0,t.jsx)(r.p,{children:"\u041f\u043e\u0441\u043b\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430, \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c \u043c\u043e\u0436\u0435\u0442 \u043f\u0440\u0438\u0441\u0442\u0443\u043f\u0430\u0442\u044c \u043a \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u044e \u0441\u043e\u0431\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0445 sgroups. \u0412 \u043a\u0430\u0447\u0435\u0441\u0442\u0432\u0435 \u043e\u0442\u043f\u0440\u0430\u0432\u043d\u043e\u0439 \u0442\u043e\u0447\u043a\u0438,\n\u0432\u043e\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u043c\u0441\u044f \u0433\u043e\u0442\u043e\u0432\u044b\u043c \u0448\u0430\u0431\u043b\u043e\u043d\u043e\u043c."})}),"\n",(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",metastring:"title='Install terraform-spec-template'",children:"git clone https://github.com/H-BF/swarm-spec-template\ncd swarm-spec-template\n"})}),"\n",(0,t.jsxs)("div",{children:[(0,t.jsxs)(r.p,{children:["\u0421\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u043c \u0448\u0430\u0433\u043e\u043c \u043d\u0430\u0441\u0442\u0440\u043e\u0438\u043c \u0444\u0430\u0439\u043b ",(0,t.jsx)(r.em,{children:"providers.tf"}),":"]}),(0,t.jsxs)("ul",{children:[(0,t.jsx)("li",{children:(0,t.jsxs)(r.p,{children:["\u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0438\u043b\u0438 ",(0,t.jsx)("a",{href:"https://github.com/H-BF/swarm-spec-template/blob/master/providers.tf#L3",children:"backend"}),",\n\u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u0431\u0443\u0434\u0435\u0442 \u0445\u0440\u0430\u043d\u0438\u0442\u044c \u0430\u043a\u0442\u0443\u0430\u043b\u044c\u043d\u044b\u0439 terraform-state."]})}),(0,t.jsx)("li",{children:(0,t.jsxs)(r.p,{children:["\u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u0443\u043a\u0430\u0437\u0430\u043b\u0438 \u0432\u0435\u0440\u0441\u0438\u044e ",(0,t.jsx)("a",{href:"https://github.com/H-BF/swarm-spec-template/blob/master/providers.tf#L8",children:"\u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440"})," \u0432 \u0441\u0435\u043a\u0446\u0438\u0438 required_providers."]})}),(0,t.jsx)("li",{children:(0,t.jsxs)(r.p,{children:["\u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u0443\u043a\u0430\u0437\u0430\u043b\u0438 ",(0,t.jsx)("a",{href:"https://github.com/H-BF/swarm-spec-template/blob/master/providers.tf#L14",children:"IP \u0430\u0434\u0440\u0435\u0441\u0441 \u0438 \u043f\u043e\u0440\u0442 hbf-server'a"}),".\n\u041b\u0438\u0431\u043e \u0443\u043a\u0430\u0436\u0438\u0442\u0435 \u0434\u0430\u043d\u043d\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0447\u0435\u0440\u0435\u0437 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u0443\u044e \u043e\u043a\u0440\u0443\u0436\u0435\u043d\u0438\u044f ",(0,t.jsx)(r.code,{children:"SGROUPS_ADDRESS"}),"."]})}),(0,t.jsx)("li",{children:(0,t.jsxs)(r.p,{children:["\u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u0443\u043a\u0430\u0437\u0430\u043b\u0438 ",(0,t.jsx)("a",{href:"https://github.com/H-BF/swarm-spec-template/blob/master/providers.tf#L15",children:"\u043f\u0435\u0440\u0438\u043e\u0434 \u0432\u0440\u0435\u043c\u0435\u043d\u0438 \u043e\u0436\u0438\u0434\u0430\u043d\u0438\u044f \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f \u043a \u0441\u0435\u0440\u0432\u0435\u0440\u0443"}),".\n\u041b\u0438\u0431\u043e \u0443\u043a\u0430\u0436\u0438\u0442\u0435 \u0434\u0430\u043d\u043d\u043e\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435 \u0447\u0435\u0440\u0435\u0437 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u0443\u044e \u043e\u043a\u0440\u0443\u0436\u0435\u043d\u0438\u044f ",(0,t.jsx)(r.code,{children:"SGROUPS_DIAL_DURATION"}),"."]})})]}),(0,t.jsxs)(r.p,{children:["\u0414\u0430\u043b\u0435\u0435 \u0443\u0431\u0435\u0434\u0438\u043c\u0441\u044f \u0432 \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e\u0439 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0435 \u0444\u0430\u0439\u043b ",(0,t.jsx)(r.em,{children:"main.tf"}),":"]}),(0,t.jsx)("ul",{children:(0,t.jsx)("li",{children:(0,t.jsxs)(r.p,{children:["\u0423\u0431\u0435\u0434\u0438\u0442\u0435\u0441\u044c, \u0447\u0442\u043e \u0432\u044b \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e \u043d\u0430\u0441\u0442\u0440\u043e\u0438\u043b\u0438 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440 ",(0,t.jsx)("a",{href:"https://github.com/H-BF/swarm-spec-template/blob/master/main.tf#L2",children:"source"}),". \u0412\u0430\u0436\u043d\u043e\u0439 \u0447\u0430\u0441\u0442\u044c \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430, \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0442\u043e, \u043a\u0443\u0434\u0430 \u0441\u0441\u044b\u043b\u0430\u0435\u0442\u0441\u044f\n\u0412\u0441\u0435 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u044b\u0435 \u0432\u0430\u0440\u0438\u0430\u043d\u0442\u044b \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u044f \u0434\u0430\u043d\u043d\u043e\u0433\u043e \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0430 \u043c\u043e\u0436\u043d\u043e \u043d\u0430\u0439\u0442\u0438 ",(0,t.jsx)("a",{href:"https://developer.hashicorp.com/terraform/language/modules/sources#github",children:"\u0432 \u043e\u0444\u0438\u0446\u0438\u0430\u043b\u044c\u043d\u043e\u0439 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u0438"}),"."]})})}),(0,t.jsxs)(r.p,{children:["\u0412\u043e\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435\u0441\u044c \u043f\u0440\u0435\u0434\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043d\u044b\u043c\u0438 \u0432 \u0440\u0435\u043f\u043e\u0437\u0438\u0442\u043e\u0440\u0438\u0438 sgroups \u0434\u043b\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0440\u0430\u0431\u043e\u0442\u043e\u0441\u043f\u043e\u0441\u043e\u0431\u043d\u043e\u0441\u0442\u0438 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430.\n\u0414\u043b\u044f \u044d\u0442\u043e\u0433\u043e \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435 \u043a\u043e\u043c\u0430\u043d\u0434\u0443 (\u0432\u0430\u0436\u043d\u043e \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u0442\u044c \u0444\u043b\u0430\u0433 ",(0,t.jsx)(r.code,{children:"--parallelism=1"}),"):"]}),(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",metastring:"title='Run terraform plan'",children:"terraform plan --parallelism=1\n"})}),(0,t.jsxs)(r.p,{children:["\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442\u043e\u043c \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0438\u044f \u043a\u043e\u043c\u0430\u043d\u0434\u044b, \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c \u0441\u043f\u0438\u0441\u043e\u043a \u0440\u0435\u0441\u0443\u0440\u0441\u043e\u0432, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u043e\u043f\u0438\u0441\u0430\u043d\u044b \u0432 \u0434\u0438\u0440\u0435\u043a\u0442\u043e\u0440\u0438\u0438 ",(0,t.jsx)(r.em,{children:"spec/"}),"."]}),(0,t.jsxs)(r.p,{children:["\u0421\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u043c \u0448\u0430\u0433\u043e\u043c \u0431\u0443\u0434\u0435\u0442 \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0435 \u0441\u043e\u0431\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0445 sgroups \u043e\u043f\u0438\u0440\u0430\u044f\u0441\u044c, \u043d\u0430 \u043f\u0440\u0438\u043c\u0435\u0440\u044b \u0438\u0437 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u0438. \u0412\u044b \u043c\u043e\u0436\u0435\u0442\u0435 \u0441\u043e\u0437\u0434\u0430\u0432\u0430\u0442\u044c \u043b\u044e\u0431\u0443\u044e \u0438\u0435\u0440\u0430\u0440\u0445\u0438\u0447\u043d\u043e\u0441\u0442\u044c \u0432 \u0434\u0438\u0440\u0435\u043a\u0442\u043e\u0440\u0438\u044e ",(0,t.jsx)(r.em,{children:"spec/"}),", \u043f\u043e\u0441\u043a\u043e\u043b\u044c\u043a\u0443 \u043f\u0440\u0438 \u043e\u043f\u0438\u0441\u0430\u043d\u0438\u0438\n\u0441\u0435\u0442\u0435\u0432\u044b\u0445 \u043f\u043e\u043b\u0438\u0442\u0438\u043a sgroups, \u043e\u043d\u0438 \u0441\u0441\u044b\u043b\u0430\u044e\u0442\u0441\u044f ",(0,t.jsx)(r.em,{children:"\u043d\u0430 \u0438\u043c\u0435\u043d\u0430 sgroups"}),", \u0430 \u043d\u0435 \u043d\u0430 \u043f\u0443\u0442\u0438 \u0440\u0430\u0441\u043f\u043e\u043b\u043e\u0436\u0435\u043d\u0438\u044f \u0444\u0430\u0439\u043b\u043e\u0432 \u0434\u043e sgroups."]}),(0,t.jsxs)(r.p,{children:["\u0414\u043b\u044f \u0442\u043e\u0433\u043e, \u0447\u0442\u043e\u0431\u044b \u043f\u0440\u0438\u043c\u0435\u043d\u0438\u0442\u044c \u043e\u043f\u0438\u0441\u0430\u043d\u043d\u044b\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u0430, \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435 \u043a\u043e\u043c\u0430\u043d\u0434\u0443 (\u0432\u0430\u0436\u043d\u043e \u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u0442\u044c \u0444\u043b\u0430\u0433 ",(0,t.jsx)(r.code,{children:"--parallelism=1"}),"):"]}),(0,t.jsx)(r.pre,{children:(0,t.jsx)(r.code,{className:"language-bash",metastring:"title='Run terraform plan'",children:"terraform apply --auto-approve --parallelism=1\n"})})]})]})}function d(e={}){const{wrapper:r}={...(0,c.R)(),...e.components};return r?(0,t.jsx)(r,{...e,children:(0,t.jsx)(p,{...e})}):p(e)}}}]);