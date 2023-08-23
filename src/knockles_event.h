#ifndef __KNOCKLES_EVENT_H__
#define __KNOCKLES_EVENT_H__

/****************************************************/
/*!
 *  \brief  Event share between CO-RE code and userland
 */
typedef struct _event_t{
    uint16_t   id;
    uint32_t   seq;
    uint16_t   win;
} event_t;

#endif
