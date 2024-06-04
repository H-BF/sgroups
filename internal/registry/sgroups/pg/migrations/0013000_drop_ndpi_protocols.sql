-- +goose Up
-- +goose StatementBegin
drop function sgroups.list_fqdn_rule;

drop view sgroups.vu_fqdn_rule;

create view sgroups.vu_fqdn_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       fqdn_to,
       proto,
       ports,
       logs,
       action,
       priority
  from sgroups.tbl_fqdn_rule as R;

create function sgroups.list_fqdn_rule (
    sgfrom sgroups.cname[] default null
) returns table (
                    sg_from sgroups.cname,
                    fqdn_to sgroups.fqdn,
                    proto sgroups.proto,
                    ports sgroups.sg_rule_ports[],
                    logs bool,
                    action sgroups.rule_action,
                    priority smallint
                )
as $$
begin
    return query select r.sg_from,
                        r.fqdn_to,
                        r.proto,
                        r.ports,
                        r.logs,
                        r.action,
                        r.priority
                   from sgroups.vu_fqdn_rule as r
                  where ( sgfrom is null or
                          r.sg_from = any (sgfrom) );
end;
$$ language plpgsql immutable;


create or replace function sgroups.sync_fqdn_rule(op sgroups.sync_op, d sgroups.row_of__fqdn_rule)
    returns boolean
as $$
declare
    ret bigint;
    sgFrom bigint;
begin
    select id from sgroups.tbl_sg where "name" = (d).sg_from into sgFrom;
    if sgFrom is null then
        raise exception 'on check SG-From it found the SG(%) not exist', (d).sg_from;
    end if;
    if op = 'del' then
        delete from sgroups.tbl_fqdn_rule
         where sg_from = sgFrom
           and fqdn_to = (d).fqdn_to
           and proto = (d).proto
     returning id into ret;
    elseif op = 'upd' then
        update sgroups.tbl_fqdn_rule
           set ports = (d).ports,
               logs = (d).logs,
               action = (d).action,
               priority = (d).priority
         where sg_from = sgFrom
           and fqdn_to = (d).fqdn_to
           and proto = (d).proto
     returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs, action, priority)
             values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs, (d).action, (d).priority)
                 on conflict
                    on constraint sg_fqdn_rule_identity
                       do update
                          set ports = (d).ports,
                              logs = (d).logs,
                              action = (d).action,
                              priority = (d).priority
     returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs, action, priority)
             values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs, (d).action, (d).priority)
                 on conflict
                    on constraint sg_fqdn_rule_identity
                       do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;

alter type sgroups.row_of__fqdn_rule
      drop attribute if exists ndpi_protocols;

alter table sgroups.tbl_fqdn_rule
       drop constraint if exists "check-ndpi-protocols";

alter table sgroups.tbl_fqdn_rule
       drop column if exists ndpi_protocols;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
