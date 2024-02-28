-- +goose Up
-- +goose StatementBegin
--------------------------------------- TABLES ---------------------------------------

drop table if exists sgroups.tbl_ie_sg_sg_rule cascade;
create table sgroups.tbl_ie_sg_sg_rule
(
    id       bigint generated always as identity primary key,
    proto    sgroups.proto   not null,
    sg_local bigint          not null,
    sg       bigint          not null,
    traffic  sgroups.traffic not null,
    ports    sgroups.sg_rule_ports[],
    logs     bool            not null,
    trace    bool            not null,
    constraint ie_sg_sg_rule_identity
        unique (proto, sg_local, sg, traffic),
    constraint fk_ie_sg_sg_rule__sg_local
        foreign key (sg_local) references sgroups.tbl_sg (id)
            on delete cascade
            on update restrict
            deferrable initially deferred,
    constraint fk_ie_sg_sg_rule__sg
        foreign key (sg) references sgroups.tbl_sg (id)
            on delete cascade
            on update restrict
            deferrable initially deferred,
    constraint "S_ports_dont_intersect"
        check (
            sgroups.s_ports_dont_intersect(ports)
            )
);

drop view if exists sgroups.vu_ie_sg_sg_rule cascade;
create or replace view sgroups.vu_ie_sg_sg_rule as
select proto,
       (select "name" from sgroups.tbl_sg where id = R.sg_local) as sg_local,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       ports,
       logs,
       trace
from sgroups.tbl_ie_sg_sg_rule as R;

--------------------------------------- READERS ---------------------------------------
drop function if exists sgroups.list_ie_sg_sg_rules(sgroups.cname[], sgroups.cname[]) cascade;
create or replace function sgroups.list_ie_sg_sg_rules (
    sglocals sgroups.cname[] default null,
    sgs sgroups.cname[] default null
) returns table ( proto sgroups.proto,
                  sg_local sgroups.cname,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  ports sgroups.sg_rule_ports[],
                  logs bool,
                  trace bool
                )
as $$
begin
    return query select r.proto,
                        r.sg_local,
                        r.sg,
                        r.traffic,
                        r.ports,
                        r.logs,
                        r.trace
                    from sgroups.vu_ie_sg_sg_rule as r
                    where( sglocals is null or r.sg_local = any(sglocals) )
                     and ( sgs is null or r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

--------------------------------------- WRITERS ---------------------------------------
drop type if exists sgroups.row_of__ie_sg_sg_rule cascade;
create type sgroups.row_of__ie_sg_sg_rule as (
    proto sgroups.proto,
    sg_local sgroups.cname,
    sg sgroups.cname,
    traffic sgroups.traffic,
    ports sgroups.sg_rule_ports[],
    logs bool,
    trace bool
);

drop function if exists sgroups.sync_ie_sg_sg_rule(sgroups.sync_op, sgroups.row_of__ie_sg_sg_rule);
create or replace function sgroups.sync_ie_sg_sg_rule(op sgroups.sync_op, d sgroups.row_of__ie_sg_sg_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgLocalID bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg_local into sgLocalID;
    if sgLocalID is null then
        raise exception 'on check SgLocal it found the SG(%) not exists', (d).sg_local;
    end if;
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check Sg it found the SG(%) not exists', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_ie_sg_sg_rule
        where proto = (d).proto
          and sg_local = sgLocalID
          and sg = sgID
          and traffic = (d).traffic
        returning id into ret;
    elseif op = 'upd' then
        update sgroups.tbl_ie_sg_sg_rule
           set ports = (d).ports,
               logs = (d).logs,
               trace = (d).trace
         where proto = (d).proto
           and sg_local = sgLocalID
           and sg = sgID
           and traffic = (d).traffic
        returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_ie_sg_sg_rule (proto, sg_local, sg, traffic, ports, logs, trace)
             values ((d).proto, sgLocalID, sgID, (d).traffic, (d).ports, (d).logs, (d).trace)
                 on conflict
                    on constraint ie_sg_sg_rule_identity
                        do update
                            set ports = (d).ports,
                                logs = (d).logs,
                                trace = (d).trace
        returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_ie_sg_sg_rule (proto, sg_local, sg, traffic, ports, logs, trace)
             values ((d).proto, sgLocalID, sgID, (d).traffic, (d).ports, (d).logs, (d).trace)
                on conflict
                    on constraint ie_sg_sg_rule_identity
                        do nothing
        returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
