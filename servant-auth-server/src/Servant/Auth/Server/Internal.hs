{-# LANGUAGE CPP #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans (liftIO)
import           Servant             ((:>), Handler, HasServer (..),
                                      Proxy (..),
                                      Context (..),
                                      HasContextEntry(getContextEntry))
import           Servant.Auth

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal (DelayedIO, addAuthCheck, withRequest)

import GHC.TypeLits (Symbol)

type family Content s where
  Content "JWTSettings"    = JWTSettings
  Content "CookieSettings" = CookieSettings
  Content "Both"           = (JWTSettings, CookieSettings)

-- Gathers the settings requested by `which` from the context
-- which can be "JWTSettings", or "CookieSettings", or "Both"
class GatherSettings (context :: [*]) (which :: Symbol) where
  result :: Context context -> Proxy which -> Maybe (Content which)

instance GatherSettings '[] p where
  result _ _ = Nothing

instance GatherSettings (CookieSettings ': cs) "CookieSettings" where
  result (cookieSettings :. _) _ = Just cookieSettings

instance GatherSettings (JWTSettings ': cs) "JWTSettings" where
  result (jwtSettings :. _) _ = Just jwtSettings

instance GatherSettings cs "JWTSettings" => GatherSettings (CookieSettings ': cs) "Both" where
  result (cookieSettings :. ctx) _ =
    case result ctx (Proxy :: Proxy "JWTSettings") of
      Nothing -> Nothing
      Just jwtSettings -> Just (jwtSettings, cookieSettings)

instance GatherSettings cs "CookieSettings" => GatherSettings (JWTSettings ': cs) "Both" where
  result (jwtSettings :. ctx) _ =
    case result ctx (Proxy :: Proxy "CookieSettings") of
      Nothing -> Nothing
      Just cookieSettings -> Just (jwtSettings, cookieSettings)

-- ignore unknown entries in the context
instance {-# OVERLAPPABLE #-} GatherSettings cs p => GatherSettings (unknown ': cs) p where
  result (_ :. ctx) _ = result ctx (Proxy :: Proxy p)

type MaybeCookieSettings ctxs = GatherSettings ctxs "Both"

instance ( n ~ 'S ('S 'Z)
         , HasServer (AddSetCookiesApi n api) ctxs, AreAuths auths ctxs v
         , HasServer api ctxs -- this constraint is needed to implement hoistServer
         , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
         , ToJWT v
         , MaybeCookieSettings ctxs
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

#if MIN_VERSION_servant_server(0,12,0)
  hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy :: Proxy api) pc nt . s
#endif

  route _ context subserver =
        -- check whether the cookie settings are present or not
        case result context (Proxy :: Proxy "Both") of
          Nothing ->
            route (Proxy :: Proxy api) context (subserver `addAuthCheck` authCheckNoCookied)
          Just (j, c) -> 
            route (Proxy :: Proxy (AddSetCookiesApi n api))
                  context
                  (fmap go subserver `addAuthCheck` (authCheck j c))

    where
      authCheckNoCookied :: DelayedIO (AuthResult v)
      authCheckNoCookied = withRequest $ \req -> liftIO $ runAuthCheck (runAuths (Proxy :: Proxy auths) context) req

      authCheck :: JWTSettings -> CookieSettings -> DelayedIO (AuthResult v, SetCookieList ('S ('S 'Z)))
      authCheck j c = withRequest $ \req -> liftIO $ do
        authResult <- runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        cookies <- makeCookies j c authResult
        return (authResult, cookies)

      makeCookies :: JWTSettings -> CookieSettings -> AuthResult v -> IO (SetCookieList ('S ('S 'Z)))
      makeCookies jwtSettings cookieSettings authResult = do
        xsrf <- makeXsrfCookie cookieSettings
        fmap (Just xsrf `SetCookieCons`) $
          case authResult of
            (Authenticated v) -> do
              ejwt <- makeSessionCookie cookieSettings jwtSettings v
              case ejwt of
                Nothing  -> return $ Nothing `SetCookieCons` SetCookieNil
                Just jwt -> return $ Just jwt `SetCookieCons` SetCookieNil
            _ -> return $ Nothing `SetCookieCons` SetCookieNil

      go :: (AuthResult v -> ServerT api Handler)
         -> (AuthResult v, SetCookieList n)
         -> ServerT (AddSetCookiesApi n api) Handler
      go fn (authResult, cookies) = addSetCookies cookies $ fn authResult
