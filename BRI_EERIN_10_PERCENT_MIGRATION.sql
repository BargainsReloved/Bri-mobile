-- One-time update for Eerin sales already recorded in the account.
-- This changes the amount owed from cost price to cost price + 10%.
-- Example: £1.50 cost becomes £1.65 owed.
update public.eerin_account
set cost_owed = round((cost_owed * 1.10)::numeric, 2)
where cost_owed is not null
  and cost_owed > 0;
