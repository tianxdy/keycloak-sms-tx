package org.keycloak.sms.auth;

import com.github.qcloudsms.SmsSingleSender;
import com.github.qcloudsms.SmsSingleSenderResult;
import com.github.qcloudsms.httpclient.HTTPException;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.requiredactions.VerifyEmail;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.services.validation.Validation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author yanfeiwuji
 * @description
 * @date 16:09  2020/2/21
 */
public class SmsUtil {

    private static final Logger logger = Logger.getLogger(VerifyEmail.class);


    public static final String SUCCESS_FLAG = "success";

    private static DefaultCacheManager _cacheManager;

    public static Cache<String, String> sms_cache = get_cache();

    private static final String SMS_CATCH_NAME = "sms-verify";

    private static final String CODE_CATCH_SUFFIX = "-code";

    private static Cache<String, String> get_cache() {
        try {
            Cache<String, String> cache = getCacheManager().getCache(SMS_CATCH_NAME);
            logger.info(cache);
            return cache;
        } catch (Exception e) {
            logger.error(e);
            e.printStackTrace(System.out);
            throw e;
        }
    }


    private static DefaultCacheManager getCacheManager() {
        if (_cacheManager == null) {
            ConfigurationBuilder config = new ConfigurationBuilder();
            _cacheManager = new DefaultCacheManager();
            _cacheManager.defineConfiguration(SMS_CATCH_NAME, config.build());
        }
        return _cacheManager;
    }


    private static final String[] NEED_KEYS = new String[]{
            SmsAuthenticatorContstants.CONF_APP_ID,
            SmsAuthenticatorContstants.CONF_APP_KEY,
            SmsAuthenticatorContstants.CONF_TWMPLATE_ID,
            SmsAuthenticatorContstants.CONF_SIGN,
            SmsAuthenticatorContstants.CONF_TEMPLATE_PARAMS,
            SmsAuthenticatorContstants.CONF_SMS_CODE_LENGTH,
            SmsAuthenticatorContstants.CONF_SMS_CODE_EXP
    };


    public static Boolean sendSms(String phoneNumber, AuthenticationFlowContext context) {

        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        String phoneHasCode = get_cache().get(phoneNumber);
        if (phoneHasCode != null) {
            return true;
        }
        if (configModel == null) {
            logger.infof("该流程中未定义短信相关参数");
            return false;
        }

        Map<String, String> config = configModel.getConfig();

        boolean allHas = Stream.of(NEED_KEYS).allMatch(k -> {
            String v = config.get(k);
            if (Validation.isBlank(v)) {
                logger.infof("流程 %s 中未配置参数 %s ", context.getFlowPath(), k);
                return false;
            } else {
                return true;
            }
        });

        if (!allHas) {
            return false;
        }

        // 缺次数校验
        String appid = config.get(SmsAuthenticatorContstants.CONF_APP_ID);
        String appKey = config.get(SmsAuthenticatorContstants.CONF_APP_KEY);
        String templateId = config.get(SmsAuthenticatorContstants.CONF_TWMPLATE_ID);
        String sign = config.get(SmsAuthenticatorContstants.CONF_SIGN);
        String templateParams = config.get(SmsAuthenticatorContstants.CONF_TEMPLATE_PARAMS);
        String smsCodeLength = config.get(SmsAuthenticatorContstants.CONF_SMS_CODE_LENGTH);
        String smsCodeExp = config.get(SmsAuthenticatorContstants.CONF_SMS_CODE_EXP);

        Integer codeLength = Integer.valueOf(smsCodeLength);
        int codeExp = Integer.parseInt(smsCodeExp);
        String code = String.valueOf((int) ((Math.random() * 9 + 1) * Math.pow(10, codeLength - 1)));


        String[] params = templateParams.split("#");

        List<String> listParams = Stream.of(params).map(i -> {
            if (i.equals("{code}")) {
                return code;
            }
            if (i.equals("{exp}")) {
                return smsCodeExp;
            }
            return i;
        }).collect(Collectors.toList());

        logger.infof("key value");
        config.forEach((k, v) -> {
            logger.infof("%s %s", k, v);
        });
        logger.infof(listParams.stream().collect(Collectors.joining("===")));
        SmsSingleSender smsSingleSender = new SmsSingleSender(Integer.valueOf(appid), appKey);

        try {
            SmsSingleSenderResult result =
                    smsSingleSender
                            .sendWithParam("86", phoneNumber, Integer.valueOf(templateId), new ArrayList<>(listParams), sign, "", "");
            logger.infof(result.toString());
            if (result.result == 0) {
                // 设置一分钟
                get_cache().put(phoneNumber, "", 1, TimeUnit.MINUTES);
                // 缓存 验证码
                get_cache().put(phoneNumber + CODE_CATCH_SUFFIX, code, codeExp, TimeUnit.MINUTES);
                logger.infof("发送验证码成功并缓存");
                return true;
            } else {
                return false;
            }
        } catch (HTTPException | IOException e) {
            e.printStackTrace();
        }
        return true;
    }


    public static String checkCode(String phoneNumber, String inputCode) {
        String code = get_cache().get(phoneNumber + CODE_CATCH_SUFFIX);
        if (code == null) {
            return "验证码已过期";
        } else {
            if (code.equals(inputCode)) {
                return SUCCESS_FLAG;
            } else {
                return "验证码输入错误";
            }
        }
    }
}
