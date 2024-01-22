-- +goose Up
-- +goose StatementBegin
alter table sgroups.tbl_fqdn_rule
        add column ndpi_protocols citext[] not null default '{}'::citext[];

create or replace view sgroups.vu_fqdn_rule as
select (select "name" from sgroups.tbl_sg where id = R.sg_from) as sg_from,
       fqdn_to,
       proto,
       ports,
       logs,
       ndpi_protocols
  from sgroups.tbl_fqdn_rule as R;


drop function if exists sgroups.list_fqdn_rule(sgroups.cname[]) cascade;
create or replace function sgroups.list_fqdn_rule (
    sgfrom sgroups.cname[] default null
) returns table (
                    sg_from sgroups.cname,
                    fqdn_to sgroups.fqdn,
                    proto sgroups.proto,
                    ports sgroups.sg_rule_ports[],
                    logs bool,
                    ndpi_protocols citext[]
                )
as $$
begin
    return query select r.sg_from,
                        r.fqdn_to,
                        r.proto,
                        r.ports,
                        r.logs,
                        r.ndpi_protocols
                   from sgroups.vu_fqdn_rule as r
                  where ( sgfrom is null or
                          r.sg_from = any (sgfrom) );
end;
$$ language plpgsql immutable;

alter type sgroups.row_of__fqdn_rule
       add attribute ndpi_protocols citext[];


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
               ndpi_protocols = (d).ndpi_protocols
         where sg_from = sgFrom
           and fqdn_to = (d).fqdn_to
           and proto = (d).proto
     returning id into ret;
    elseif op = 'ups' then
        insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs, ndpi_protocols)
             values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs, (d).ndpi_protocols)
                 on conflict
                    on constraint sg_fqdn_rule_identity
                       do update
                          set ports = (d).ports,
                              logs = (d).logs,
                              ndpi_protocols = (d).ndpi_protocols
     returning id into ret;
    elseif op = 'ins' then
        insert into sgroups.tbl_fqdn_rule (sg_from, fqdn_to, proto, ports, logs, ndpi_protocols)
             values (sgFrom, (d).fqdn_to, (d).proto, (d).ports, (d).logs, (d).ndpi_protocols)
                 on conflict
                    on constraint sg_fqdn_rule_identity
                       do nothing
     returning id into ret;
    end if;
    return ret is not null;
end;
$$ language plpgsql strict;


drop function if exists sgroups.check_ndpi_protocols(citext[]);
create or replace function sgroups.check_ndpi_protocols(pp citext[])
    returns boolean
as $$
declare
    cnt int;
    bad citext;
begin
    select coalesce(array_length(pp, 1), 0) into cnt;
    if cnt > 255 then
        raise exception 'protocol count is (%) but it must be <= 255', cnt;
    end if;
    with x(p) as (
      select unnest(pp)
    ) select p
        from x
       where not(p ~ '^\S')
          or not(p ~ '\S$')
          or coalesce(length(p), 0) = 0
        into bad;
    if bad is not null then
        raise exception 'bad protocol name `%`', bad;
    end if;
    return true;
end;
$$ language plpgsql immutable;

alter table sgroups.tbl_fqdn_rule
        add constraint "check-ndpi-protocols"
            check (
                sgroups.check_ndpi_protocols(ndpi_protocols)
            );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
