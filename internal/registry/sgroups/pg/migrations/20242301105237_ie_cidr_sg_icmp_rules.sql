-- +goose Up
-- +goose StatementBegin
--------------------------------------- TABLES ---------------------------------------
drop table if exists sgroups.tbl_cidr_sg_icmp_rule cascade;
create table sgroups.tbl_cidr_sg_icmp_rule (
    id      bigint generated always as identity primary key,
    ip_v    sgroups.ip_family  not null,
    types   sgroups.icmp_types not null,
    cidr    cidr               not null,
    sg      bigint             not null,
    traffic sgroups.traffic    not null,
    logs    bool               not null,
    trace   bool               not null,
    constraint cidr_sg_icmp_rule_identity
        unique (ip_v, cidr, sg, traffic),
    constraint fk_cidr_sg_icmp_rule__sg
       foreign key (sg) references sgroups.tbl_sg (id)
            on delete cascade
            on update restrict
            deferrable initially deferred,
    constraint "prevent_cidrs_intersections_over(ip_v,sg,traffic)"
       exclude using GIST (
          ip_v with =,
          cidr inet_ops with &&,
          sg with =,
          traffic with =
       ) deferrable initially deferred,
    constraint "cidr_and_ipv_consistency"
        check (
               (ip_v = 'IPv4'::sgroups.ip_family and family(cidr) = 4)
            or (ip_v = 'IPv6'::sgroups.ip_family and family(cidr) = 6)
        )
);

drop view if exists sgroups.vu_cidr_sg_icmp_rule cascade;
create or replace view sgroups.vu_cidr_sg_icmp_rule as
select ip_v,
       types,
       cidr,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       logs,
       trace
from sgroups.tbl_cidr_sg_icmp_rule as R;

--------------------------------------- READERS ---------------------------------------
drop function if exists sgroups.list_cidr_sg_icmp_rules(sgroups.cname[]) cascade;
create or replace function sgroups.list_cidr_sg_icmp_rules (
    sgs sgroups.cname[] default null
) 
  returns table ( ip_v sgroups.ip_family,
                  types sgroups.icmp_types,
                  cidr cidr,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  logs bool,
                  trace bool
                )
as $$
begin
    return query select r.ip_v,
                        r.types,
                        r.cidr,
                        r.sg,
                        r.traffic,
                        r.logs,
                        r.trace
                   from sgroups.vu_cidr_sg_icmp_rule as r
                  where ( sgs is null or r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

--------------------------------------- WRITERS ---------------------------------------
drop type if exists sgroups.row_of__cidr_sg_icmp_rule cascade;
create type sgroups.row_of__cidr_sg_icmp_rule as (
    ip_v sgroups.ip_family,
    types sgroups.icmp_types,
    cidr cidr,
    sg sgroups.cname,
    traffic sgroups.traffic,
    logs bool,
    trace bool
);

drop function if exists sgroups.sync_cidr_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__cidr_sg_icmp_rule) cascade;
create or replace function sgroups.sync_cidr_sg_icmp_rule(op sgroups.sync_op, d sgroups.row_of__cidr_sg_icmp_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check SG it found the SG(%) not exists', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_cidr_sg_icmp_rule
         where ip_v = (d).ip_v
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'upd' then
        update sgroups.tbl_cidr_sg_icmp_rule
           set types = (d).types,
               logs  = (d).logs,
               trace = (d).trace
         where ip_v = (d).ip_v
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elseif op = 'ups' then
        insert 
          into sgroups.tbl_cidr_sg_icmp_rule (ip_v, types, cidr, sg, traffic, logs, trace)
        values ((d).ip_v, (d).types, (d).cidr, sgID, (d).traffic, (d).logs, (d).trace)
        on conflict
           on constraint cidr_sg_icmp_rule_identity
              do update
                    set types = (d).types,
                        logs  = (d).logs,
                        trace = (d).trace
              returning id into ret;
    elseif op = 'ins' then
        insert 
          into sgroups.tbl_cidr_sg_icmp_rule (ip_v, types, cidr, sg, traffic, logs, trace)
        values ((d).ip_v, (d).types, (d).cidr, sgID, (d).traffic, (d).logs, (d).trace)
            on conflict
               on constraint cidr_sg_icmp_rule_identity
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
