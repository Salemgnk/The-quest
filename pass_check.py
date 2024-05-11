import string
import random
from displayer import *

specials = "~#{([_-@]*!£$;,:/?)}"
input_text = ""

def pass_checker(input):
    special = False
    upper = False
    lenght = False

    if len(input) < 8:
        print("Your password is too short")
    else:
        lenght = True
    for i in input:
        for j in specials:
            if i == j:
                special = True
        if i.isupper():
            upper = True
    if special == True and upper == True and lenght == True:
        print("Good Password")
    else:
        print("This password need to be changed")

def display_screen(screen):
    screen.fill((0, 0, 0))
    displayer(screen, "Enter your password:")

    # font = pygame.font.Font(None, 36)
    # text_surface = font.render(input_text, True, (255, 255, 255))
    # text_rect = text_surface.get_rect()
    # text_rect.center = (screen.get_width() // 2, screen.get_height() // 2)  # Centrer le texte dans l'écran
    # pygame.draw.rect(screen, (0, 0, 255), text_rect, 2)  # Dessiner un rectangle autour du texte
    # screen.blit(text_surface, text_rect)  # Afficher le texte

    pygame.display.flip()

    for event in pygame.event.get():
        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_BACKSPACE and len(input_text) > 0:
                input_text = input_text[:-1]
            elif event.key == pygame.K_RETURN:
                pass_checker(input_text)
                input_text = ""
            elif event.unicode.isprintable():
                input_text += event.unicode
                displayer(screen, input_text)
                pygame.display.flip()
