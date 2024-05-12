import pygame

white = (255, 255, 255)
black = (0, 0, 0)
blue = (0, 0, 128)
 
def displayer(screen, input):
    font = pygame.font.Font(None, 36)
    text = font.render(input, True, white)
    textRect = text.get_rect()
    textRect.center = (screen.get_width() // 2, screen.get_height() - 950)
    screen.blit(text, textRect)