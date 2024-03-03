package com.anst.sd.api.security.fw;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import(WebSecurityConfig.class)
public @interface EnableAuthLibSecurity {
}
