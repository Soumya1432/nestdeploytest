import {  BadRequestException, Injectable } from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { CreateTodoDto } from './dto/create-todo.dto';

@Injectable()
export class TodoService {
    constructor(private readonly databaseService: DatabaseService) { }

    async fetchAllTodo() {
        const fetchData = await this.databaseService.todo.findMany({
            where: {
                deletedAt: null,
            },
        });
        return fetchData;
    }


    async fetchTodoById(id: string) {
        const fetchData = await this.databaseService.todo.findFirst({
            where: { id, deletedAt: null },
        });
        return fetchData;
    }

    async createTodo(createTodoDto: CreateTodoDto) {
        const res = await this.databaseService.todo.create({
            data: {
                title: createTodoDto.title,
                description: createTodoDto.description,
            },
        });
        return { res };
    }

    async updateTodo(createTodoDto: CreateTodoDto, id: string) {
        const updateById = await this.databaseService.todo.update({
            where: { id: id },
            data: {
                title: createTodoDto.title,
                description: createTodoDto.description,
            },
        });
        return updateById;
    }

   async deleteById(id: string) {
    console.log("Request to delete ID:", id);

    const record = await this.databaseService.todo.findFirst({
        where: { id, deletedAt: null },
    });

    if (!record) {
        throw new BadRequestException('Id not found or already deleted');
    }

    const response = await this.databaseService.todo.update({
        where: { id },
        data: { deletedAt: new Date() },
    });

    console.log("Updated record:", response);

    return response;
}

}
