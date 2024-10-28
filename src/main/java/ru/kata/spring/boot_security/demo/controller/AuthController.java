package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import ru.kata.spring.boot_security.demo.entity.Role;
import ru.kata.spring.boot_security.demo.entity.User;
import ru.kata.spring.boot_security.demo.service.RegistrationServiceImpl;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.RoleServiceImpl;
import ru.kata.spring.boot_security.demo.util.UserValidator;

import javax.validation.Valid;
import java.util.List;

@Controller
public class AuthController {
    private final UserValidator userValidator;
    private final RegistrationServiceImpl registrationServiceImpl;
    private final RoleServiceImpl roleServiceImpl;

    @Autowired
    public AuthController(UserValidator userValidator, RegistrationServiceImpl registrationServiceImpl, RoleServiceImpl roleServiceImpl) {
        this.userValidator = userValidator;
        this.registrationServiceImpl = registrationServiceImpl;
        this.roleServiceImpl = roleServiceImpl;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "/login";
    }

    @GetMapping("/registration")
    public String registerPage(@ModelAttribute("user") User user, Model model) {
        List<Role> roles = roleServiceImpl.findAllRoles();
        model.addAttribute("roles", roles);
        return "/registration";
    }

    @PostMapping("/registration")
    public String performLogin(@ModelAttribute("user") @Valid User user,
                               BindingResult bindingResult) {
        userValidator.validate(user, bindingResult);

        if (bindingResult.hasErrors()) {
            return "/registration";
        }

        registrationServiceImpl.register(user);

        return "redirect:/login";
    }
}
