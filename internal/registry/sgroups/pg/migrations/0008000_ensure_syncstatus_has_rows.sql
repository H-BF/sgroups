-- +goose Up
-- +goose StatementBegin
insert into sgroups.tbl_sync_status(total_affected_rows) (
    select 1 where not exists(select 1 from sgroups.tbl_sync_status)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT no-down-scenarion;
-- +goose StatementEnd
