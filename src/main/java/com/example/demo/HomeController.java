package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.validation.Valid;

@Controller
public class HomeController {
    @Autowired
    MessageRepository messageRepository;

    @RequestMapping("/")
    public String listMessage(Model model) {
        model.addAttribute("messages", messageRepository.findAll());
        return "list";
    }

    @GetMapping("/add")
    public String messageForm(Model model) {
        model.addAttribute("messageobject", new Message());
        return "messageform";
    }

    @PostMapping("/process")
    public String processForm(@Valid @ModelAttribute("messageobject") Message message, BindingResult result) {
        if (result.hasErrors()) {
            return "messageform";
        }
        messageRepository.save(message);
        return "redirect:/";
    }
}