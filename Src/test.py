import pygame
import string
from displayer import *
from pass_check import *
import os

os.environ["XDG_SESSION_TYPE"] = "xcb"
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
specials = "~#{([_-@]*!£$;,:/?)}"

def is_valid_password(password):
    if len(password) < 8:
        return False
    specials = set(string.punctuation)
    if not any(char in specials for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False    
    if not any(char.isdigit() for char in password):
        return False    
    return True

def pass_checker(input, screen):
    special = False
    upper = False
    lenght = False

    if is_valid_password(input) == True:
        pic_displayer(screen, "ressources/SECURED.png")
        start_time = pygame.time.get_ticks()
        while pygame.time.get_ticks() - start_time < 1000:
            pass
        screen.fill(BLACK)
        pygame.display.flip()
    else:
        pic_displayer(screen, "ressources/weak.png")
        start_time = pygame.time.get_ticks()
        while pygame.time.get_ticks() - start_time < 2000:
            pass
        screen.fill(BLACK)
        pygame.display.flip()

def pic_displayer(screen, filepath):
    back = pygame.image.load(filepath).convert()
    scaled_image = pygame.transform.scale(back, screen.get_size())
    screen.blit(scaled_image, (0, 0))
    pygame.display.update()

def check_pass(screen):
    font = pygame.font.Font(None, 36)
    input_rect = pygame.Rect(750, 200, 400, 50)
    input_text = ''

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_BACKSPACE and len(input_text) > 0:
                    input_text = input_text[:-1]
                elif event.key == pygame.K_RETURN:
                    pass_checker(input_text, screen)
                elif event.unicode.isprintable():
                    input_text += event.unicode
        
        screen.fill(BLACK)
        displayer(screen, "Enter your password:")
        pygame.draw.rect(screen, WHITE, input_rect, 2)
        
        text_surface = font.render(input_text, True, WHITE)
        screen.blit(text_surface, (input_rect.x + 5, input_rect.y + 5))
        pygame.display.flip()

