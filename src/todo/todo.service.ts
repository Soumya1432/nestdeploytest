import { Injectable } from '@nestjs/common';
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
        const response = await this.databaseService.todo.delete({
            where: { id },
            data: { deletedAt: new Date() },
        });
        return response;
    }

}
