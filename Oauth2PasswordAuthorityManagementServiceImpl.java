package com.zhcx.apiroute.authorizationmodel.impl;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser.Feature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.context.RequestContext;
import com.zhcx.apiroute.authorizationmodel.Oauth2AuthorizationModelAuthorityManagementService;
import com.zhcx.apiroute.util.FixedAuthResProperties;
import com.zhcx.apiroute.util.WhiteListProperties;
import com.zhcx.commons.authority.bean.AuthUserResp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import javax.annotation.Resource;
import java.net.URLEncoder;
import java.util.*;

/**
 * password 密码模式
 * 
 * @title
 * @author 龚进
 * @date 2019年5月23日
 * @version 1.0
 */
@Service
public class Oauth2PasswordAuthorityManagementServiceImpl
		implements Oauth2AuthorizationModelAuthorityManagementService {

	private static ObjectMapper mapper = new ObjectMapper();
	static {
		mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		mapper.setTimeZone(TimeZone.getTimeZone("GMT+8"));
		mapper.configure(Feature.ALLOW_UNQUOTED_CONTROL_CHARS, true);
		mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
	}
	
	// 这是一个测试注释

	@Resource(name = "redisTemplate4Json")
	private RedisTemplate<String, Object> redisTemplate;
	
	@Autowired
	private FixedAuthResProperties fixedAuthResProperties;
	
	@Autowired
	private WhiteListProperties whiteListProperties;

	@Override
	@SuppressWarnings({ "unchecked" })
	public boolean matchAuthority(String requestType, String requestUri) {
		if ("OPTIONS".equalsIgnoreCase(requestType)) {
			return true;
		}
		// 如果uri的最后一个字符串位/,则去掉/
		if (requestUri.endsWith("/")) {
			requestUri = requestUri.substring(0, requestUri.length() - 1);
		}
		AntPathMatcher matcher = new AntPathMatcher();
		/**
		// 通配符匹配匿名访问地址
		List<String> urls = AuthFileUtils.getInstance().getValues();
		if (null != urls && urls.size() > 0) {
			for (String url : urls) {
				if (matcher.match(url, requestUri)) {
					return true;
				}
			}
		}
		*/
		
		// 修改通配符匹配匿名访问地址 从Nacos 中获取,不带登录即可访问
		List<Map<String,String>> fixedAuthResValues = fixedAuthResProperties.getFixedAuthResValues();
        if (null != fixedAuthResValues && !fixedAuthResValues.isEmpty()) {
			for (Map<String, String> url : fixedAuthResValues) {
				if (url.containsKey(requestType.toUpperCase())
						&& matcher.match(url.get(requestType.toUpperCase()), requestUri)) {
					return true;
				
				}
			}
		}
		
        
		/**
		// 通配符匹配白名单地址
		List<String> whiteListurls = WhiteListFileUtils.getInstance().getValues();
		if (null != whiteListurls && whiteListurls.size() > 0) {
			for (String url : whiteListurls) {
				if (matcher.match(url, requestUri)) {
					return true;
				}
			}
		}
		*/
		// 修改配符匹配白名单地址 从Nacos 中获取_2019年8月23日_登录后即可访问
		List<Map<String,String>> whiteListValues = whiteListProperties.getWhiteListValues();
        if (null != whiteListValues && !whiteListValues.isEmpty()) {
			for (Map<String, String> url : whiteListValues) {
				if (url.containsKey(requestType.toUpperCase())
						&& matcher.match(url.get(requestType.toUpperCase()), requestUri)) {
					return true;
				}
			}
		}
		
		// 获取用户信息
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (null != authentication && authentication instanceof OAuth2Authentication) {
			OAuth2Authentication oauth = (OAuth2Authentication) authentication;
			// 用户信息
			LinkedHashMap<String, Object> details = (LinkedHashMap<String, Object>) oauth.getUserAuthentication()
					.getDetails();
			LinkedHashMap<String, Object> userAuthentication = (LinkedHashMap<String, Object>) details
					.get("userAuthentication");
			LinkedHashMap<String, Object> user = (LinkedHashMap<String, Object>) userAuthentication.get("details");
			String corpId = user.get("corpId").toString();
			String userId = user.get("userId").toString();
			// 获取账号和用户类型
			String accountName = String.valueOf(user.get("accountName"));
			String userType = String.valueOf(user.get("userType"));
			if("admin".equals(accountName) && "01".equals(userType)) {
				// 如果账号是admin并且用户类型是01，就直接放行，拥有所有权限
				return true;
			}
			
			// 企业用户角色
			String corpUserRole = String.format("user:role:%s", corpId);
			// 从redis读取用户角色权限
			BoundHashOperations<String, String, Object> operations = redisTemplate.boundHashOps(corpUserRole);
			Object roleIds = operations.get(userId);
			if (null == roleIds) {
				return false;
			}
			String[] roleIdArr = roleIds.toString().split(",");
			// 角色功能权限
			String corpRoleFunction = String.format("role:function:%s", corpId);
			// 从redis中读取企业角色功能
			operations = redisTemplate.boundHashOps(corpRoleFunction);
			for (String roleId : roleIdArr) {
				List<String> functionUrls = null == operations.get(roleId) ? Collections.EMPTY_LIST
						: (List<String>) operations.get(roleId);
				for (String functionUrl : functionUrls) {
					// 如果uri的最后一个字符串位/,则去掉/
					if (functionUrl.endsWith("/")) {
						functionUrl = functionUrl.substring(0, functionUrl.length() - 1);
					}
					if (requestType.equalsIgnoreCase(functionUrl.substring(0, functionUrl.indexOf("#")))
							&& matcher.match(functionUrl.substring(functionUrl.indexOf("#") + 1), requestUri)) {
						return true;
					}
				}
			}
			// 从redis中读取公共角色功能
			corpRoleFunction = String.format("role:function:%s", 0);
			operations = redisTemplate.boundHashOps(corpRoleFunction);
			for (String roleId : roleIdArr) {
				List<String> functionUrls = null == operations.get(roleId) ? Collections.EMPTY_LIST
						: (List<String>) operations.get(roleId);
				for (String functionUrl : functionUrls) {
					// 如果uri的最后一个字符串位/,则去掉/
					if (functionUrl.endsWith("/")) {
						functionUrl = functionUrl.substring(0, functionUrl.length() - 1);
					}
					if (requestType.equalsIgnoreCase(functionUrl.substring(0, functionUrl.indexOf("#")).trim())
							&& matcher.match(functionUrl.substring(functionUrl.indexOf("#") + 1).trim(), requestUri)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void setCustomHeaderInfo(OAuth2Authentication oAuth2Authentication) throws Exception {
		LinkedHashMap<String, Object> details = (LinkedHashMap<String, Object>) oAuth2Authentication
				.getUserAuthentication().getDetails();
		LinkedHashMap<String, Object> userAuthentication = (LinkedHashMap<String, Object>) details
				.get("userAuthentication");
		LinkedHashMap<String, Object> user = (LinkedHashMap<String, Object>) userAuthentication.get("details");
		String json = mapper.writeValueAsString(user);
		AuthUserResp authUserResp = mapper.readValue(json, AuthUserResp.class);
		// 去掉一些特殊属性，不让他携带在请求头中
		authUserResp.setUserImg(null);

		String value = mapper.writeValueAsString(authUserResp);
		// 对用户进行编码，中文乱码
		String encode = URLEncoder.encode(value,"utf-8");
		// token值
		String token = ((OAuth2AuthenticationDetails) oAuth2Authentication.getDetails()).getTokenValue();
		RequestContext requestContext = RequestContext.getCurrentContext();
		// 设置用户信息
		/** 扫码测试，断开老的方式
		requestContext.addZuulRequestHeader(token, value);
		*/
		requestContext.addZuulRequestHeader("Token"+token,encode);
	}
}
