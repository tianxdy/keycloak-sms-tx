package org.keycloak.sms.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.Response;

/**
 * @author yanfeiwuji
 * @description
 * @date 15:09  2020/2/21
 */
public class SmsAuthenticator implements Authenticator {

    private static Logger logger = Logger.getLogger(SmsAuthenticator.class);
    private static final String PAGE_FTL = "phone-verify.ftl";

    private static final String FLOW_REGISTRATION = "registration";
    private static final String FLOW_REST_CREDENTIALS = "reset-credentials";
    private static final String FLOW_FIRST_BROKER_LOGIN = "first-broker-login";

    private static final String SUBMIT_GETCODE = "getcode";
    private static final String SUBMIT_OK = "ok";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LoginFormsProvider loginFormsProvider = context.form();
        setScene(context, loginFormsProvider);
        Response challenge = loginFormsProvider.createForm(PAGE_FTL);
        context.challenge(challenge);
    }


    @Override
    public void action(AuthenticationFlowContext context) {


        logger.infof("action plow  %s", context.getFlowPath());

        String flowPath = context.getFlowPath();
        String phone = (context.getHttpRequest().getDecodedFormParameters().getFirst("phone"));
        String submitAction = (context.getHttpRequest().getDecodedFormParameters().getFirst("submitAction"));
        LoginFormsProvider loginFormsProvider = context.form();
        setScene(context, loginFormsProvider);
        loginFormsProvider.setAttribute("phone", phone);

        String code = (context.getHttpRequest().getDecodedFormParameters().getFirst("code"));

        if (Validation.isBlank(phone)) {
            setError("请输入手机号", context, loginFormsProvider);
            return;
        }
        if (phone.length() != 11) {
            setError("请输入正确的手机号", context, loginFormsProvider);
            return;
        }
        switch (flowPath) {
            case FLOW_REGISTRATION:
                logger.infof("注册");
                UserModel newUser = context.getSession().users().getUserByUsername(phone, context.getRealm());
                if (newUser != null) {
                    setError("该手机号已被注册", context, loginFormsProvider);
                    return;
                }
                break;
            case FLOW_REST_CREDENTIALS:
                UserModel oldUser = context.getSession().users().getUserByUsername(phone, context.getRealm());
                if (oldUser == null) {
                    setError("该手机号未注册", context, loginFormsProvider);
                    return;
                }
                break;
            default:
        }

        switch (submitAction) {
            case SUBMIT_GETCODE:
                logger.infof("发送验证码");
                context.getAuthenticatorConfig();
                boolean su = SmsUtil.sendSms(phone, context);
                if (su) {
                    loginFormsProvider.setAttribute("sendCode", true);
                    setSuccess("发送验证码成功", context, loginFormsProvider);
                    return;
                } else {
                    setError("发送未知错误", context, loginFormsProvider);
                }
                return;
            case SUBMIT_OK:
                String msg = SmsUtil.checkCode(phone, code);
                if (SmsUtil.SUCCESS_FLAG.equals(msg)) {
                    // 说明成功
                    UserModel user;
                    if (FLOW_REST_CREDENTIALS.equals(flowPath)) {
                        user = context.getSession().users().getUserByUsername(phone, context.getRealm());
                    } else if (FLOW_REGISTRATION.equals(flowPath)) {
                        user = context.getSession().users().addUser(context.getRealm(), phone);
                    } else if (FLOW_FIRST_BROKER_LOGIN.equals(flowPath)) {
                        user = context.getSession().users().getUserByUsername(phone, context.getRealm());
                        if (user == null) {
                            user = context.getSession().users().addUser(context.getRealm(), phone);
                        }
                    } else {
                        // no
                        setError(msg, context, loginFormsProvider);
                        return;
                    }
                    user.setEnabled(true);
                    context.setUser(user);
                    context.getEvent().user(user);
                    context.getEvent().success();
                    context.newEvent().event(EventType.LOGIN);
                    context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                            .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                            .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
                    String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
                    if (authType != null) {
                        context.getEvent().detail(Details.AUTH_TYPE, authType);
                    }
                    context.success();
                    return;
                } else {
                    setError("验证码错误", context, loginFormsProvider);
                    return;
                }
        }

    }


    private void setScene(AuthenticationFlowContext context, LoginFormsProvider loginFormsProvider) {
        String flowPath = context.getFlowPath();
        switch (flowPath) {
            case FLOW_REGISTRATION:
                loginFormsProvider.setAttribute("scene", "注册");
                return;
            case FLOW_REST_CREDENTIALS:
                loginFormsProvider.setAttribute("scene", "重置密码");
                return;
            case FLOW_FIRST_BROKER_LOGIN:
                loginFormsProvider.setAttribute("scene", "绑定/注册新用户");
            default:
                return;
        }
    }

    private void setError(String msg, AuthenticationFlowContext context, LoginFormsProvider loginFormsProvider) {
        Response response = loginFormsProvider
                .addError(new FormMessage(msg))
                .createForm(PAGE_FTL);
        context.challenge(response);
    }

    private void setSuccess(String msg, AuthenticationFlowContext context, LoginFormsProvider loginFormsProvider) {
        Response response = loginFormsProvider
                .addSuccess(new FormMessage(msg))
                .createForm(PAGE_FTL);
        context.challenge(response);
    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    // 提供手机号
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.infof("set req ");
        // logger.info("setRequiredActions");
        // user.addRequiredAction(PhoneActionFactory.PROVIDER_ID);
    }


    @Override
    public void close() {
    }
}
