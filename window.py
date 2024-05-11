import pygame
import tkinter as tk

white = (255, 255, 255)
black = (0, 0, 0)
blue = (0, 0, 128)

def displayer(screen):
    font = pygame.font.Font(None, 36)
    text = font.render('Welcome on Upsilon Tools. What do you want to do ?', True, white)
    textRect = text.get_rect()
    textRect.center = (screen.get_width() // 2, screen.get_height() - 950)
    screen.blit(text, textRect)

 
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

def buttons_choice(screen):
    pic_displayer(screen)
    draw_rectangle(screen, "Password Checker", [100, 250, 400, 100], (300, 300))
    draw_rectangle(screen, "Password Generator", [100, 600, 400, 100], (300, 650))
    draw_rectangle(screen, "Navigator", [1400, 250, 400, 100], (1600, 300))
    draw_rectangle(screen, "Pentest Tools", [1400, 600, 400, 100], (1600, 650))



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
    buttons_choice(screen)
    display = True

    while display:
        displayer(screen)
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                display = False
        displayer(screen)
        pygame.display.flip()
        framerate.tick(30)
    pygame.quit()


window()
