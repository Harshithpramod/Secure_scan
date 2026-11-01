-- Removes the API key feature.
--
-- Keys could be created in Settings but nothing ever consumed them — no
-- endpoint authenticated with a `pta_` key — so the UI was an attractive
-- nuisance: users could mint a credential that did nothing. The UI and server
-- functions are gone; this drops the storage behind them.
--
-- DESTRUCTIVE: this deletes every stored key hash. That is the intent (the
-- hashes are unusable), but it cannot be undone. If you would rather keep the
-- table around as dead storage, simply don't run this file — nothing in the
-- app references it any more either way.

DROP VIEW IF EXISTS public.api_keys_public;
DROP TABLE IF EXISTS public.api_keys;
