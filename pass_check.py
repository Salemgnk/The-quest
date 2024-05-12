import string
import random
import sys
from displayer import *
from test import *

input_text = ""
display = True

def display_screen(screen):
    screen.fill((0, 0, 0))
    displayer(screen, "Enter your password:")

    input_rect = pygame.Rect(200, 200, 400, 50)
    font = pygame.font.Font(None, 36)

    pygame.draw.rect(screen, white, input_rect, 2)        
    # Afficher le texte entré
    text_surface = font.render(input_text, True, white)
    screen.blit(text_surface, (input_rect.x + 5, input_rect.y + 5))

    pygame.display.flip()
