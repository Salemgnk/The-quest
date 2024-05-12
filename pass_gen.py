import string
import random
import pygame
import pyperclip
from displayer import *

specials = "~#{([_-@]*!£$;,:/?)}"
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)

def pass_gen(screen):
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
                    length = max(int(input_text), 8)
                    mdp = ''.join(random.sample(string.ascii_letters + string.digits + specials, length))
                    pyperclip.copy(mdp)
                    font = pygame.font.Font(None, 36)
                    text = font.render(f"Password generated: {mdp}", True, white)
                    textRect = text.get_rect()
                    textRect.center = (screen.get_width() // 2, screen.get_height() - 850)
                    screen.blit(text, textRect)
                    pygame.display.flip()
                    pygame.time.delay(3000)
                elif event.unicode.isdigit() and len(input_text) < 2:
                    input_text += event.unicode

        screen.fill(BLACK)
        displayer(screen, "Enter password length (min 8):")
        pygame.draw.rect(screen, WHITE, input_rect, 2)
        font = pygame.font.Font(None, 36)
        text_surface = font.render(input_text, True, WHITE)
        screen.blit(text_surface, (input_rect.x + 5, input_rect.y + 5))
        pygame.display.flip()

