import pygame

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

def draw_rectangle(screen):
    pygame.draw.rect(screen, (0, 0, 255), [100, 100, 400, 100], 2)

def window():
    pygame.init()
    screen = pygame.display.set_mode((1920, 1080), pygame.RESIZABLE)
    framerate = pygame.time.Clock()
    pygame.display.set_caption("Upsilon Solutions")
    icon = pygame.image.load("upsilon.jpg").convert()
    pygame.display.set_icon(icon)

    fade_in(icon, screen)
    pygame.time.delay(2000)
    fade_out(icon, screen)     
    display = True

    while display:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                display = False
            
        framerate.tick(30)
    pygame.quit()


window()