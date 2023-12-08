-- +goose Up
-- +goose StatementBegin
create extension if not exists btree_gist;
--------------------------------------- TYPES ---------------------------------------
drop type if exists sgroups.traffic cascade;
create type sgroups.traffic as enum (
    'ingress',
    'egress'
);
--------------------------------------- TABLES ---------------------------------------
drop table if exists sgroups.tbl_cidr_sg_rule cascade;
create table sgroups.tbl_cidr_sg_rule (
    id bigint generated always as identity primary key,
    proto sgroups.proto not null,
    cidr cidr not null,
    sg bigint not null,
    traffic sgroups.traffic not null,
    ports sgroups.sg_rule_ports[],
    logs bool not null,
    trace bool not null,
    constraint cidr_sg_rule_identity
        unique (proto, cidr, sg, traffic),
    constraint fk_cidr_sg_rule___sg
       foreign key(sg) references sgroups.tbl_sg(id)
               on delete cascade
               on update restrict
               deferrable initially deferred,
    constraint "S_ports_dont_intersect"
         check (
             sgroups.s_ports_dont_intersect(ports)
         ),
    constraint "prevent_cidrs_intersections_over(proto,sg,traffic)"
       exclude using GIST (
                   proto with =,
                   cidr inet_ops with &&,
                   sg with =,
                   traffic with =
               ) deferrable initially deferred
);

drop view if exists sgroups.vu_cidr_sg_rule cascade;
create or replace view sgroups.vu_cidr_sg_rule as
select proto,
       cidr,
       (select "name" from sgroups.tbl_sg where id = R.sg) as sg,
       traffic,
       ports,
       logs,
       trace
  from sgroups.tbl_cidr_sg_rule as R;

--------------------------------------- READERS ---------------------------------------
drop function if exists sgroups.list_cidr_sg_rule(sgroups.cname[]) cascade;
create or replace function sgroups.list_cidr_sg_rule (
    sgs sgroups.cname[] default null
) returns table ( proto sgroups.proto,
                  cidr cidr,
                  sg sgroups.cname,
                  traffic sgroups.traffic,
                  ports sgroups.sg_rule_ports[],
                  logs bool,
                  trace bool
                )
as $$
begin
    return query select r.proto,
                        r.cidr,
                        r.sg,
                        r.traffic,
                        r.ports,
                        r.logs,
                        r.trace
                   from sgroups.vu_cidr_sg_rule as r
                  where ( sgs is null or
                          r.sg = any(sgs) );
end;
$$ language plpgsql immutable;

--------------------------------------- WRITERS ---------------------------------------
drop type if exists sgroups.row_of__cidr_sg_rule cascade;
create type sgroups.row_of__cidr_sg_rule as (
    proto sgroups.proto,
    cidr cidr,
    sg sgroups.cname,
    traffic sgroups.traffic,
    ports sgroups.sg_rule_ports[],
    logs bool,
    trace bool
);

drop function if exists sgroups.sync_cidr_sg_rule(sgroups.sync_op, sgroups.row_of__cidr_sg_rule);
create or replace function sgroups.sync_cidr_sg_rule(op sgroups.sync_op, d sgroups.row_of__cidr_sg_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgID bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg into sgID;
    if sgID is null then
        raise exception 'on check SG it found the SG(%) not exist', (d).sg;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_cidr_sg_rule
         where proto = (d).proto
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elsif op = 'upd' then
        update sgroups.tbl_cidr_sg_rule
           set ports = (d).ports,
               logs = (d).logs,
               trace = (d).trace
         where proto = (d).proto
           and cidr = (d).cidr
           and sg = sgID
           and traffic = (d).traffic
     returning id into ret;
    elsif op = 'ups' then
        insert into sgroups.tbl_cidr_sg_rule (proto, cidr, sg, traffic, ports, logs, trace)
             values ((d).proto, (d).cidr, sgID, (d).traffic ,(d).ports, (d).logs, (d).trace)
                 on conflict
                    on constraint cidr_sg_rule_identity
                       do update
                          set ports = (d).ports,
                              logs = (d).logs,
                              trace = (d).trace
     returning id into ret;
    elsif op = 'ins' then
        insert into sgroups.tbl_cidr_sg_rule (proto, cidr, sg, traffic, ports, logs, trace)
             values ((d).proto, (d).cidr, sgID, (d).traffic ,(d).ports, (d).logs, (d).trace)
                 on conflict
                     on constraint cidr_sg_rule_identity
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
