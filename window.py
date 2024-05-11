from pass_gen import *
import pygame
import tkinter as tk
from pass_check import *
from displayer import *

def fade_in(image, screen):
    alpha = 0
    while alpha < 255:
        screen.fill((255, 255, 255))
        image.set_alpha(alpha)
        scaled_image = pygame.transform.scale(image, screen.get_size())
        screen.blit(scaled_image, (0, 0))
        pygame.display.flip()
        pygame.time.delay(10)
        alpha += 5

def fade_out(image, screen):
    alpha = 255
    while alpha > 0:
        screen.fill((255, 255, 255))
        image.set_alpha(alpha)
        scaled_image = pygame.transform.scale(image, screen.get_size())
        screen.blit(scaled_image, (0, 0))
        pygame.display.flip()
        pygame.time.delay(10)
        alpha -= 5

def pic_displayer(screen):
    back = pygame.image.load("back.png").convert()
    scaled_image = pygame.transform.scale(back, screen.get_size())
    screen.blit(scaled_image, (0, 0))
    pygame.display.update()

def draw_rectangle(screen, input, pos, text_pos):
    pygame.draw.rect(screen, (0, 0, 255), pos, 2)
    font = pygame.font.Font(None, 36)
    text_surface = font.render(input, True, (255, 255, 255))
    text_rect = text_surface.get_rect()
    text_rect.center = text_pos
    screen.blit(text_surface, text_rect)
    pygame.display.update()

def buttons_display(screen):
    pic_displayer(screen)
    draw_rectangle(screen, "Password Checker", [100, 250, 400, 100], (300, 300))
    draw_rectangle(screen, "Password Generator", [100, 600, 400, 100], (300, 650))
    draw_rectangle(screen, "Navigator", [1400, 250, 400, 100], (1600, 300))
    draw_rectangle(screen, "Pentest Tools", [1400, 600, 400, 100], (1600, 650))


def buttons_choice(screen, mouse_pos):
    rect_positions = [
        {"name": "Password Checker", "pos": [100, 250, 400, 100]},
        {"name": "Password Generator", "pos": [100, 600, 400, 100]},
        {"name": "Navigator", "pos": [1400, 250, 400, 100]},
        {"name": "Pentest Tools", "pos": [1400, 600, 400, 100]}
    ]
    for rect_data in rect_positions:
        pos = rect_data["pos"]
        if pygame.Rect(pos).collidepoint(mouse_pos):
            if rect_data["name"] == "Password Checker":
                display_screen(screen)

def window():
    pygame.init()
    screen = pygame.display.set_mode((1920, 1080), pygame.RESIZABLE)
    framerate = pygame.time.Clock()
    pygame.display.set_caption("Upsilon Solutions")
    icon = pygame.image.load("upsilon.png").convert()
    pygame.display.set_icon(icon)

    fade_in(icon, screen)
    pygame.time.delay(2000)
    fade_out(icon, screen)
    buttons_display(screen)
    display = True
    input_text = ""

    displayer(screen, 'Welcome on Upsilon Tools. What do you want to do ?')
    while display:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                display = False
            elif event.type == pygame.MOUSEBUTTONDOWN:
                mouse_pos = pygame.mouse.get_pos()
                buttons_choice(screen, mouse_pos)
        pygame.display.flip()
        framerate.tick(30)
    pygame.quit()


window()
